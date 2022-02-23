if node.attribute.fetch('teleport_token', '').length > 0

    teleport node.name do
        action          :setup
        initial_token   node.attribute['teleport_token']
        operator        node.normal['tags'].find {|t| t.start_with?('cloudletorg')}.split("/")[1].downcase
    end

else

    teleport node.name do
        action  :destroy
    end

end
