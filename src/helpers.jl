function brainwallet(passphrase; rounds=1, hash_func=sha256, pre_func=identity)::String
    private_key = passphrase
    for i in 1:rounds
        private_key = hash_func(private_key)
    end
    private_key = bytes2hex(private_key)
    if length(private_key) < 64
        private_key = lpad(private_key, 64, "0")
    end
    return private_key
end

function read_balance_dict(filename; delim='\t', eol='\n', header=false, skipstart=1)
    balances = readdlm(filename, delim, String, eol; header=header, skipstart=skipstart)
    return Dict(pubkey => parse(Int, balance) for (pubkey, balance) in eachrow(balances))
end

function check_balance(balance_dict::Dict, wallet::Wallet)
    return check_balance(balance_dict, wallet.addresses)
end

function check_balance(balance_dict::Dict, private_key::PrivateKey)
    return check_balance(balance_dict, BTCAddresses(private_key))
end

function check_balance(balance_dict::Dict, addresses::BTCAddresses)
    for address in [addresses.p2pkh, addresses.p2pkh_c, addresses.p2sh_c, addresses.bech32]
        return check_balance(balance_dict, address)
    end
end

function check_balance(balance_dict::Dict, address)
    if address in keys(balance_dict) && balance_dict[address] > 0
        return balance_dict[address]
    else
        return 0
    end
end
