using Reseau

const CC = Base.Compiler
const NC = Reseau.TCP

function stmt_summary(stmt)
    if stmt isa Core.EnterNode
        return "EnterNode(catch_dest=$(stmt.catch_dest))"
    elseif stmt isa Expr && stmt.head === :leave
        args = join(map(stmt.args) do arg
            if arg === nothing
                return "nothing"
            elseif arg isa Core.SSAValue
                return "SSA($(arg.id))"
            end
            return repr(arg)
        end, ", ")
        return "Expr(:leave, $args)"
    elseif stmt isa Expr && stmt.head === :pop_exception
        args = join(map(stmt.args) do arg
            arg isa Core.SSAValue ? "SSA($(arg.id))" : repr(arg)
        end, ", ")
        return "Expr(:pop_exception, $args)"
    elseif stmt isa Core.GotoNode
        return "GotoNode($(stmt.label))"
    elseif stmt isa Core.GotoIfNot
        return "GotoIfNot(dest=$(stmt.dest))"
    elseif stmt isa Core.ReturnNode
        return "ReturnNode($(isdefined(stmt, :val) ? repr(stmt.val) : "<undef>"))"
    end
    return repr(stmt)
end

function print_special_statements(ci::Core.CodeInfo)
    println("[rootcause] relevant lowered statements")
    for (idx, stmt) in pairs(ci.code)
        if stmt isa Core.EnterNode ||
           stmt isa Core.GotoNode ||
           stmt isa Core.GotoIfNot ||
           stmt isa Core.ReturnNode ||
           (stmt isa Expr && stmt.head in (:leave, :pop_exception))
            println("[rootcause]   ", lpad(idx, 3), " | ", stmt_summary(stmt))
        end
    end
    return nothing
end

function debug_compute_trycatch(code::Vector{Any}, bbs::Union{Vector{CC.BasicBlock}, Nothing}=nothing)
    n = length(code)
    ip = BitSet()
    ip.offset = 0
    push!(ip, n + 1)
    handler_info = nothing

    for pc = 1:n
        stmt = code[pc]
        if isa(stmt, Core.EnterNode)
            (; handlers, handler_at) = handler_info =
                (handler_info === nothing ? CC.HandlerInfo{CC.TryCatchFrame}(CC.TryCatchFrame[], fill((0, 0), n)) : handler_info)
            l = stmt.catch_dest
            (bbs !== nothing) && (l != 0) && (l = first(bbs[l].stmts))
            push!(handlers, CC.TryCatchFrame(stmt, pc))
            handler_id = length(handlers)
            handler_at[pc + 1] = (handler_id, 0)
            push!(ip, pc + 1)
            if l != 0
                handler_at[l] = (0, handler_id)
                push!(ip, l)
            end
            println("[rootcause] seed enter pc=$pc handler_id=$handler_id mapped_catch_dest=$l")
        end
    end

    handler_info === nothing && return false
    (; handlers, handler_at) = handler_info

    while true
        pc = CC._bits_findnext(ip.bits, 0)::Int
        pc > n && break
        while true
            pc_next = pc + 1
            delete!(ip, pc)
            cur_stacks = handler_at[pc]
            stmt = code[pc]
            if isa(stmt, Core.GotoNode)
                pc_next = stmt.label
                (bbs !== nothing) && (pc_next = first(bbs[pc_next].stmts))
            elseif isa(stmt, Core.GotoIfNot)
                l = stmt.dest::Int
                (bbs !== nothing) && (l = first(bbs[l].stmts))
                if handler_at[l] != cur_stacks
                    handler_at[l] = cur_stacks
                    push!(ip, l)
                end
            elseif isa(stmt, Core.ReturnNode)
                break
            elseif isa(stmt, Core.EnterNode)
                l = stmt.catch_dest
                (bbs !== nothing) && (l != 0) && (l = first(bbs[l].stmts))
                if l != 0
                    handler_at[l] = (cur_stacks[1], handler_at[l][2])
                end
                cur_stacks = (handler_at[pc_next][1], cur_stacks[2])
            elseif isa(stmt, Expr)
                head = stmt.head
                if head === :leave
                    println("[rootcause] visiting leave pc=$pc cur_stacks=$cur_stacks stmt=$(stmt_summary(stmt))")
                    leave_targets = Int[]
                    l = 0
                    for arg in stmt.args
                        if arg === nothing
                            continue
                        end
                        ssa = arg::Core.SSAValue
                        enter_stmt = code[ssa.id]
                        println("[rootcause]   leave arg SSA($(ssa.id)) -> $(stmt_summary(enter_stmt))")
                        if enter_stmt === nothing
                            continue
                        end
                        @assert isa(enter_stmt, Core.EnterNode) "malformed :leave"
                        l += 1
                        push!(leave_targets, ssa.id)
                    end
                    cur_hand = cur_stacks[1]
                    for pop_idx = 1:l
                        if cur_hand == 0
                            println("[rootcause]   UNDERFLOW at pc=$pc pop_idx=$pop_idx cur_stacks=$cur_stacks leave_targets=$leave_targets")
                            println("[rootcause]   handler table snapshot:")
                            for (hid, handler) in enumerate(handlers)
                                enter_idx = CC.get_enter_idx(handler)
                                println("[rootcause]     handler_id=$hid enter_idx=$enter_idx handler_at_enter=$(handler_at[enter_idx]) stmt=$(stmt_summary(code[enter_idx]))")
                            end
                            return true
                        end
                        enter_idx = CC.get_enter_idx(handlers[cur_hand])
                        outer = handler_at[enter_idx][1]
                        println("[rootcause]   pop #$pop_idx cur_hand=$cur_hand enter_idx=$enter_idx outer=$outer")
                        cur_hand = outer
                    end
                    cur_stacks = (cur_hand, cur_stacks[2])
                    cur_stacks == (0, 0) && break
                elseif head === :pop_exception
                    println("[rootcause] visiting pop_exception pc=$pc cur_stacks=$cur_stacks stmt=$(stmt_summary(stmt))")
                    cur_stacks = (cur_stacks[1], handler_at[(stmt.args[1]::Core.SSAValue).id][2])
                    cur_stacks == (0, 0) && break
                end
            end

            pc_next > n && break
            if handler_at[pc_next] != cur_stacks
                handler_at[pc_next] = cur_stacks
            elseif !in(pc_next, ip)
                break
            end
            pc = pc_next
        end
    end

    return false
end

function analyze_method(name::AbstractString, f, argtypes::Type)
    println("[rootcause] ===== analyzing $name =====")
    cis = code_lowered(f, argtypes)
    println("[rootcause] codeinfos=$(length(cis))")
    any_underflow = false
    for (idx, ci) in enumerate(cis)
        println("[rootcause] -- codeinfo $idx")
        print_special_statements(ci)
        try
            CC.ComputeTryCatch{CC.TryCatchFrame}()(ci.code)
            println("[rootcause] ComputeTryCatch completed without error")
        catch err
            println("[rootcause] ComputeTryCatch threw:")
            showerror(stdout, err, catch_backtrace())
            println()
            any_underflow |= debug_compute_trycatch(ci.code)
        end
    end
    return any_underflow
end

underflow_found = false
underflow_found |= analyze_method(
    "TCP.connect(::SocketAddrV4)",
    NC.connect,
    Tuple{NC.SocketAddrV4},
)
underflow_found |= analyze_method(
    "TCP._connect_socketaddr_impl(::SocketAddrV4, Nothing, Int64, Nothing)",
    NC._connect_socketaddr_impl,
    Tuple{NC.SocketAddrV4, Nothing, Int64, Nothing},
)

underflow_found || error("expected a ComputeTryCatch underflow, but no underflow was reproduced")
println("[rootcause] reproduced handler underflow")
