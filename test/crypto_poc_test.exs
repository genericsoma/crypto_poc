defmodule CryptoPocTest do
  use ExUnit.Case
  doctest CryptoPoc
  alias CryptoPoc, as: CP

  @test_message """
  Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod \
  tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, \
  quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo \
  consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse \
  cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat \
  non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
  """

  def generate_key do
    {:ok, key} = ExCrypto.generate_aes_key(:aes_256, :bytes)
    key
  end

  test "generate key" do
    assert bit_size(generate_key()) == 256
  end

  test "roundtrip" do
    key = generate_key()
    encrypted = CryptoPoc.encrypt(key, @test_message)
    assert CryptoPoc.decrypt(key, encrypted) == @test_message
  end

  test "DH test" do
    {aS, aP} = CP.dh_pair() # Alice
    {bS, bP} = CP.dh_pair() # Bob
    aK = CP.dh_key(bP, aS)
    bK = CP.dh_key(aP, bS)
    assert bit_size(aK) == 256
    assert aK == bK
  end

  test "register key" do
    CP.start_link()
    key = generate_key()
    id = "user1"
    CP.register_key(id, key)
    assert CP.get_key(id) == key
    CP.shutdown()
  end

  test "delete key" do
    CP.start_link()
    key = generate_key()
    id = "user1"
    CP.register_key(id, key)
    CP.forget_key(id)
    assert CP.get_key(id) == nil
    CP.shutdown()
  end

  test "key timeout" do
    CP.start_link()
    key = generate_key()
    id = "user1"
    CP.register_key(id, key, 1_000)
    assert CP.get_key(id) == key
    Process.sleep(2_000)
    assert CP.get_key(id) == nil
    CP.shutdown()
  end
end
