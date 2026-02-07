const XML_MAX_DOCUMENT_DEPTH = 20
const XML_MAX_NAME_LEN = 256
const XML_MAX_ATTRIBUTES = 10

struct XmlAttribute
    name::ByteCursor
    value::ByteCursor
end

struct XmlNode
    name::ByteCursor
    attributes::ArrayList{XmlAttribute}
    body::ByteCursor
    is_empty::Bool
    depth::Int
    max_depth::Int
end

struct XmlParserOptions{F}
    doc::ByteCursor
    max_depth::Int
    on_root::F
end

XmlParserOptions(on_root, doc::ByteCursor, max_depth::Integer = 0) =
    XmlParserOptions(doc, Int(max_depth), on_root)

const xml_attribute = XmlAttribute
const xml_node = XmlNode
const xml_parser_options = XmlParserOptions

# Helper to access byte at index in Memory (0-based index for C-style parsing)
@inline function _byte_at(mem::Memory{UInt8}, idx::Int)
    return @inbounds mem[idx + 1]  # Convert 0-based to 1-based
end

# Create a ByteCursor from Memory at a given offset (0-based) with given length
@inline function _cursor_from_mem(mem::Memory{UInt8}, offset::Int, len::Int)
    if len <= 0
        return null_cursor()
    end
    return ByteCursor(Csize_t(len), memoryref(mem, offset + 1))  # Convert 0-based to 1-based
end

@inline function _find_byte(mem::Memory{UInt8}, start::Int, len::Int, byte::UInt8)
    i = start
    while i < len
        if _byte_at(mem, i) == byte
            return i
        end
        i += 1
    end
    return nothing
end

@inline function _is_space(byte::UInt8)
    return byte == UInt8(' ') || byte == UInt8('\t') || byte == UInt8('\n') || byte == UInt8('\r')
end

function _skip_whitespace(mem::Memory{UInt8}, i::Int, len::Int)
    while i < len && _is_space(_byte_at(mem, i))
        i += 1
    end
    return i
end

function _parse_name(mem::Memory{UInt8}, i::Int, len::Int)
    start = i
    while i < len
        b = _byte_at(mem, i)
        if _is_space(b) || b == UInt8('>') || b == UInt8('/') || b == UInt8('=')
            break
        end
        i += 1
    end
    name_len = i - start
    if name_len <= 0 || name_len > XML_MAX_NAME_LEN
        return nothing
    end
    return (start, name_len, i)
end

function _parse_attributes(mem::Memory{UInt8}, i::Int, len::Int)
    attrs = ArrayList{XmlAttribute}()
    while i < len
        i = _skip_whitespace(mem, i, len)
        i >= len && return nothing
        b = _byte_at(mem, i)
        if b == UInt8('>')
            return attrs, false, i + 1
        elseif b == UInt8('/') && i + 1 < len && _byte_at(mem, i + 1) == UInt8('>')
            return attrs, true, i + 2
        end

        parsed = _parse_name(mem, i, len)
        parsed === nothing && return nothing
        name_start, name_len, i = parsed

        i = _skip_whitespace(mem, i, len)
        i >= len && return nothing
        _byte_at(mem, i) == UInt8('=') || return nothing
        i += 1

        i = _skip_whitespace(mem, i, len)
        i >= len && return nothing
        delim = _byte_at(mem, i)
        (delim == UInt8('"') || delim == UInt8('\'')) || return nothing
        i += 1

        value_start = i
        while i < len && _byte_at(mem, i) != delim
            i += 1
        end
        i >= len && return nothing
        value_len = i - value_start
        i += 1

        attrs.length == XML_MAX_ATTRIBUTES && return nothing
        name_cur = _cursor_from_mem(mem, name_start, name_len)
        value_cur = _cursor_from_mem(mem, value_start, value_len)
        push_back!(attrs, XmlAttribute(name_cur, value_cur))
    end
    return nothing
end

function _skip_decl(mem::Memory{UInt8}, i::Int, len::Int, decl_byte::UInt8)
    i += 1
    if decl_byte == UInt8('?')
        while i + 1 < len
            if _byte_at(mem, i) == UInt8('?') && _byte_at(mem, i + 1) == UInt8('>')
                return i + 2
            end
            i += 1
        end
        return len
    end
    while i < len && _byte_at(mem, i) != UInt8('>')
        i += 1
    end
    return min(i + 1, len)
end

function _names_equal(a::ByteCursor, b::ByteCursor)
    return byte_cursor_eq(a, b)
end

function _parse_node(mem::Memory{UInt8}, len::Int, start::Int, depth::Int, max_depth::Int)
    depth > max_depth && return ErrorResult(ERROR_INVALID_XML)
    start >= len && return ErrorResult(ERROR_INVALID_XML)
    _byte_at(mem, start) == UInt8('<') || return ErrorResult(ERROR_INVALID_XML)
    start + 1 >= len && return ErrorResult(ERROR_INVALID_XML)
    _byte_at(mem, start + 1) != UInt8('/') || return ErrorResult(ERROR_INVALID_XML)

    i = start + 1
    parsed = _parse_name(mem, i, len)
    parsed === nothing && return ErrorResult(ERROR_INVALID_XML)
    name_start, name_len, i = parsed
    name_cur = _cursor_from_mem(mem, name_start, name_len)

    parsed_attrs = _parse_attributes(mem, i, len)
    parsed_attrs === nothing && return ErrorResult(ERROR_INVALID_XML)
    attrs, is_empty, i = parsed_attrs

    if is_empty
        node = XmlNode(name_cur, attrs, null_cursor(), true, depth, max_depth)
        return node, i
    end

    body_start = i
    while i < len
        if _byte_at(mem, i) == UInt8('<')
            i + 1 >= len && return ErrorResult(ERROR_INVALID_XML)
            next_byte = _byte_at(mem, i + 1)
            if next_byte == UInt8('/')
                close_start = i + 2
                parsed_close = _parse_name(mem, close_start, len)
                parsed_close === nothing && return ErrorResult(ERROR_INVALID_XML)
                close_name_start, close_name_len, close_i = parsed_close
                close_cur = _cursor_from_mem(mem, close_name_start, close_name_len)
                close_i = _skip_whitespace(mem, close_i, len)
                close_i >= len && return ErrorResult(ERROR_INVALID_XML)
                _byte_at(mem, close_i) == UInt8('>') || return ErrorResult(ERROR_INVALID_XML)
                _names_equal(name_cur, close_cur) || return ErrorResult(ERROR_INVALID_XML)
                body_len = i - body_start
                body_cur = _cursor_from_mem(mem, body_start, body_len)
                node = XmlNode(name_cur, attrs, body_cur, false, depth, max_depth)
                return node, close_i + 1
            elseif next_byte == UInt8('?') || next_byte == UInt8('!')
                i = _skip_decl(mem, i + 1, len, next_byte)
                continue
            else
                child = _parse_node(mem, len, i, depth + 1, max_depth)
                child isa ErrorResult && return child
                _child_node, next_i = child
                i = next_i
                continue
            end
        end
        i += 1
    end
    return ErrorResult(ERROR_INVALID_XML)
end

function _skip_preamble(mem::Memory{UInt8}, len::Int)
    i = 0
    while i < len
        i = _skip_whitespace(mem, i, len)
        i >= len && return len
        if _byte_at(mem, i) != UInt8('<')
            i += 1
            continue
        end
        i + 1 >= len && return len
        next_byte = _byte_at(mem, i + 1)
        if next_byte == UInt8('?') || next_byte == UInt8('!')
            i = _skip_decl(mem, i + 1, len, next_byte)
            continue
        end
        return i
    end
    return len
end

function xml_node_get_name(node::XmlNode)
    return node.name
end

function xml_node_get_num_attributes(node::XmlNode)
    return node.attributes.length
end

function xml_node_get_attribute(node::XmlNode, index::Integer)
    idx = Int(index) + 1
    idx < 1 && return XmlAttribute(null_cursor(), null_cursor())
    idx > node.attributes.length && return XmlAttribute(null_cursor(), null_cursor())
    return node.attributes.data[idx]
end

function xml_node_as_body(node::XmlNode, out::Base.RefValue{ByteCursor})
    out[] = node.body
    return OP_SUCCESS
end

function xml_node_as_body(node::XmlNode)
    return node.body
end

function xml_node_traverse(node::XmlNode, callback)
    node.is_empty && return OP_SUCCESS
    body = node.body
    len = Int(body.len)
    len == 0 && return OP_SUCCESS

    # Get the underlying Memory from the MemoryRef
    mem = parent(body.ptr)
    # The body.ptr points to the start of the body within the original document
    # Convert to 0-based base offset for the parsing functions
    base_offset = memref_offset(body.ptr) - 1

    # Helper functions that work with base_offset
    # NOTE: Use different variable name (pos) to avoid Julia scoping issue where
    # the inner function would modify the outer i variable
    @inline function find_byte_in_body(start::Int, byte::UInt8)
        pos = start
        while pos < len
            if @inbounds mem[base_offset + pos + 1] == byte
                return pos
            end
            pos += 1
        end
        return nothing
    end

    @inline function byte_at_body(idx::Int)
        return @inbounds mem[base_offset + idx + 1]
    end

    i = 0
    while i < len
        next_lt = find_byte_in_body(i, UInt8('<'))
        next_lt === nothing && return raise_error(ERROR_INVALID_XML)
        next_gt = find_byte_in_body(i, UInt8('>'))
        if next_gt === nothing || next_lt >= next_gt
            return raise_error(ERROR_INVALID_XML)
        end

        i = next_lt
        i + 1 >= len && return raise_error(ERROR_INVALID_XML)
        next_byte = byte_at_body(i + 1)
        if next_byte == UInt8('/') || next_byte == UInt8('?') || next_byte == UInt8('!')
            # Skip declaration: find the end
            i += 2
            if next_byte == UInt8('?')
                while i + 1 < len
                    if byte_at_body(i) == UInt8('?') && byte_at_body(i + 1) == UInt8('>')
                        i += 2
                        break
                    end
                    i += 1
                end
            else
                while i < len && byte_at_body(i) != UInt8('>')
                    i += 1
                end
                i = min(i + 1, len)
            end
            continue
        end

        # Parse child node using absolute indices in the original Memory
        # We need to parse from base_offset + i in the original Memory
        abs_start = base_offset + i
        abs_len = Base.length(mem)
        child = _parse_node(mem, abs_len, abs_start, node.depth + 1, node.max_depth)
        child isa ErrorResult && return raise_error(child.code)
        child_node, abs_next_i = child
        rv = callback(child_node)
        if rv isa ErrorResult || rv == OP_ERR
            return OP_ERR
        end
        # Convert absolute position back to relative position within body
        i = abs_next_i - base_offset
    end
    return OP_SUCCESS
end

function xml_parse(options::XmlParserOptions)
    doc = options.doc
    len = Int(doc.len)
    len == 0 && return raise_error(ERROR_INVALID_XML)

    # Get the underlying Memory from the ByteCursor
    mem = parent(doc.ptr)
    # Get the base offset (convert 1-based MemoryRef offset to 0-based for our parsing)
    base_offset = memref_offset(doc.ptr) - 1

    # Calculate total length available for parsing from the base offset
    total_len = Base.length(mem)

    start = _skip_preamble(mem, total_len)
    start >= total_len && return raise_error(ERROR_INVALID_XML)
    max_depth = options.max_depth == 0 ? XML_MAX_DOCUMENT_DEPTH : options.max_depth
    node = _parse_node(mem, total_len, start, 1, max_depth)
    node isa ErrorResult && return raise_error(node.code)
    root, _next_i = node
    rv = options.on_root(root)
    if rv isa ErrorResult || rv == OP_ERR
        return OP_ERR
    end
    return OP_SUCCESS
end
