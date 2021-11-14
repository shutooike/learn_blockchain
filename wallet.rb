require 'ecdsa'
require 'securerandom'
require 'digest'
require 'base58'

class Wallet
  attr_reader :public_key

  def initialize
    group = ECDSA::Group::Secp256k1

    @private_key = 1 + SecureRandom.random_number(group.order - 1)
    @public_key = group.generator.multiply_by_scalar(private_key)
  end

  def address
    @address if @address

    compressed_public_key = prefix + public_key.x.to_s(16)
    hashed_public_key = double_hash(compressed_public_key)
    hashed_public_key_with_network_byte = '00' + hashed_public_key
    row_address = hashed_public_key_with_network_byte + checksum(hashed_public_key_with_network_byte)
    @address = Base58.binary_to_base58([row_address].pack('H*'), :bitcoin)

    @address
  end

  private
  attr_reader :private_key

  def prefix
    public_key.y.even? ? '02' : '03'
  end

  def double_hash(key)
    sha256 = Digest::SHA256.hexdigest([key].pack('H*'))
    Digest::RMD160.hexdigest([sha256].pack('H*'))
  end

  def checksum(key)
    double_sha256 = double_hash(key)
    double_sha256[0..7]
  end
end
