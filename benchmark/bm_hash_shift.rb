h = {}

10000.times do |i|
  h[i] = nil
end

1000000.times do
  k, v = h.shift
  h[k] = v
end
