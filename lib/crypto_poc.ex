defmodule CryptoPoc do
  @moduledoc """
  POC of transport encryption.

  See unit test "send_receive_test.exc" for a use case.
  """

  require Logger
  require Integer
  import Bitwise
  @name __MODULE__

  ### ENCRYPTION SECTION ###

  @key_size 256

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
    # IV is 128 bits for AES
    {:ok, <<iv:: bitstring-size(128), cipher_text:: binary>>} = Base.decode64(msg64)
    {:ok, plain_text} = ExCrypto.decrypt(key, iv, cipher_text)
    plain_text
  end

  ### DIFFIE-HELLMAN SECTION ###

  # Safe prime generated by openssl dhparam -C 1024
  def dh_p, do: 
      0xABBA88AB3D950BCDDC94230A_A01AA9987D69AC0E71B4A4B9_BDA56582DABE6DF4933FAEAB_718006B44F1D2633EF20DBFB_064B9815FD873AB077890821_1D7E9B6666650236618E98AA_12E34AFCF0A2165F4108B447_DCCF818D51E5506FAC4B0632_23F0B74FE723ADA037EBE263_F7BF483635319E0D1D424A48_0A651B6BCA702FDB

  # Generator
  @dh_g 4

  # Modular exponentiation, right-to-left binary method
  defp modexp(b, e, m), do: modexp(b, e, m, 1)
  defp modexp(_b, 0, _m, r), do: r
  defp modexp(b, e, m, r) do
    b = rem(b, m)
    r = if(rem(e, 2) == 1, do: rem(r * b, m), else: r)
    modexp(b * b, e >>> 1, m, r)
  end

  # Helper for calculating the public key.
  defp dh_exp_p(g, a) do
    modexp(g, a, dh_p())
  end

  @doc """
  Generates a random secret key for use with DH.
  """
  def dh_new do
    ExCrypto.rand_int(2, dh_p() - 2)
  end

  @doc """
  Generates the public key from a secret DH key.
  """
  def dh_pub(aS) do
    dh_exp_p(@dh_g, aS)
  end

  @doc """
  Generates a DH secret-public pair.
  """
  def dh_pair do
    aS = dh_new()
    aP = dh_pub(aS)
    {aS, aP}
  end

  @doc """
  Returns the shared secret key (as binary) for a public `bP`. The key is a SHA256 of DH result.
  """
  def dh_key(bP, aS) do
    {:ok, key} = dh_exp_p(bP, aS) |>
      num_to_bin |>
      String.pad_leading(div(@key_size, 8), <<0>>) |>
      ExCrypto.Hash.sha256
    key
  end

  ### KEY MANAGEMENT SECTION ###

  @doc """
  Starts child processes for shared key handling.
  """
  def start_link do
    Logger.info "starting key management"
    {:ok, agent_pid} = Agent.start_link(fn -> %{} end, name: @name)
    proc_pid = spawn_link @name, :handler, []
    Process.register(proc_pid, :crypto_poc_proc)
    agent_pid
  end

  @doc """
  Returns registered shared key for `id` (or nil if no such id).
  """
  def get_key(id) do
    case Agent.get(@name, fn m -> Map.get(m, id) end) do
      {key, _} -> key
      nil -> nil
    end
  end

  defp get_timer_pid(id) do
    case Agent.get(@name, fn m -> Map.get(m, id) end) do
      {_, timer_pid} -> timer_pid
      nil -> nil
    end
  end

  @doc """
  Registers the shared key. If it already exists, old key is replaced with new.

  `id` is a unique identification of a user session and must be validated previously
  `key` is a bitstring of size @key_size
  """
  def register_key(id, key, timeout \\ :infinity) when bit_size(key) == @key_size do
    Logger.info "register key for id: " <> id
    # Cancel previous timeout if any
    old_timer_pid = get_timer_pid(id)
    if old_timer_pid != nil, do: Process.cancel_timer(old_timer_pid)
    timer_pid = if(timeout != :infinity, do: set_timeout(id, timeout), else: nil)
    Agent.update(@name, fn m -> Map.put(m, id, {key, timer_pid}) end)
  end

  @doc """
  Releases registered shared key.
  """
  def forget_key(id) do
    Logger.info "releasing key for id: " <> id
    case Agent.get_and_update(@name, fn m -> Map.pop(m, id) end) do
      {_, nil} -> :ok
      {_, timer_pid} -> Process.cancel_timer(timer_pid)
      _ ->
        Logger.error "error releasing key, id=" <> id
        :error
    end
  end

  # Handler for processing timeouts
  def handler do
    receive do
      {:timeout, id} ->
        Logger.debug "timeout message received for id: " <> id
        forget_key(id)
        handler()
      {:shutdown} -> shutdown()
      msg ->
        Logger.error "unrecognized message: " <> inspect(msg)
        handler()
    end
  end

  @doc """
  Sets timeout for releasing registered shared key.
  """
  def set_timeout(id, timeout) do
    Process.send_after(:crypto_poc_proc, {:timeout, id}, timeout)
  end

  @doc """
  Resets timeout, if there is the timer is alive.
  """
  def reset_timeout(id, timeout) do
    case Agent.get(@name, fn m -> Map.get(m, id) end) do
      {_, nil} -> :ok
      {key, timer_pid} ->
        Process.cancel_timer(timer_pid)
        timer_pid = Process.send_after(:crypto_poc_proc, {:timeout, id}, timeout)
        Agent.update(@name, fn m -> Map.put(m, id, {key, timer_pid}) end)
        :ok
      nil -> :fail # expired already
    end
  end

  @doc """
  Stops child processes.
  """
  def shutdown do
    Logger.info "shutting down"
    Agent.stop(@name)
    send :crypto_poc_proc, {:shutdown}
    Process.unregister(:crypto_poc_proc)
  end

  ### HELPERS/MISC SECTION ###

  # Helper for num_to_bin
  defp n2b(0, <<>>), do: <<0>>
  defp n2b(0, r), do: r
  defp n2b(n, r) do
    r = <<rem(n, 256)>> <> r
    n2b(n >>> 8, r)
  end

  # Number to binary convertion
  def num_to_bin(n) do
    n |> n2b(<<>>)
  end

  # Binary to hex string
  def bin_to_str(b) do
    sz = bit_size(b)
    <<n:: size(sz)>> = b
    Integer.to_string(n, 16)
  end

  # Normal exponent (not needed, was used for debugging)
  def pow(_, 0), do: 1
  def pow(a, b) do
    if Integer.is_even(b) do
      pow(a * a, div(b, 2))
    else
      a * pow(a, b - 1)
    end
  end
end
