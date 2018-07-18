defmodule CryptoPocTest do
  use ExUnit.Case
  doctest CryptoPoc

  @message """
  Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod \
  tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, \
  quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo \
  consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse \
  cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat \
  non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
  """

  test "generate key" do
    assert bit_size(CryptoPoc.generate_key) == 256
  end
  
  test "roundtrip" do
    key = CryptoPoc.generate_key
    encrypted = CryptoPoc.encrypt(key, @message)
    assert CryptoPoc.decrypt(key, encrypted) == @message
  end
end
