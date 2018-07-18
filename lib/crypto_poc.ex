defmodule CryptoPoc do
  @moduledoc """
  POC of transport encryption.
  """

  @key_size 256

  @doc """
  Returns a new encryption key.
  """
  def generate_key do
    {:ok, key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
    key
  end

  @doc """
  Encrypt `msg` using `key`, returns base64 encoded result.
  """
  def encrypt(key, msg) when bit_size(key) == @key_size do
    {:ok, {iv, cipher_text}} = ExCrypto.encrypt(key, msg)
    Base.encode64(iv <> cipher_text)
  end

  @doc """
  Decrypts base64-encoded payload from `msg64`, returns original message.
  """
  def decrypt(key, msg64) when bit_size(key) == @key_size do
    {:ok, <<iv:: binary-size(16), cipher_text:: binary>>} = Base.decode64(msg64)
    {:ok, plain_text} = ExCrypto.decrypt(key, iv, cipher_text)
    plain_text
  end

end
