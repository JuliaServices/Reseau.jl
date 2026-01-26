abstract type AbstractCache{K,V} end

get!(::AbstractCache{K,V}, ::K, default::V) where {K,V} = default
put!(::AbstractCache{K,V}, ::K, ::V) where {K,V} = nothing
remove!(::AbstractCache{K,V}, ::K) where {K,V} = nothing
clear!(::AbstractCache) = nothing
cache_count(::AbstractCache) = 0
