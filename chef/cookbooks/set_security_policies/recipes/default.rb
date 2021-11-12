execute("Disable ubuntu user password expiry") do
  command "chage -M -1 ubuntu"
end
