defmodule SendReceiveTest do
  use ExUnit.Case
  alias CryptoPoc, as: CP

  # Client mockup
  defmodule Client do
    use GenServer

    def start_link(id), do: GenServer.start_link(__MODULE__, id)

    def handshake(pid), do: GenServer.call(pid, :handshake)

    def send_secret(pid, message), do: GenServer.call(pid, {:message, message})

    @impl true
    def init(id) do
      bS = CP.dh_new()
      {:ok, %{id: id, secret: bS}}
    end

    @impl true
    def handle_call(:handshake, _from, %{id: id, secret: bS}) do
      IO.puts "(client) sending handshake request"
      bP = CP.dh_pub(bS)
      aP = GenServer.call(:server, {:handshake, id, bP})
      key = CP.dh_key(aP, bS)
      IO.puts "(client) shared key generated: " <> CP.bin_to_str(key)
      {:reply, {:ok, key}, %{id: id, key: key}}
    end

    @impl true
    def handle_call({:message, message}, _from, state = %{id: id, key: key}) do
      IO.puts "(client) sending message: " <> message
      secret_message = CP.encrypt(key, message)
      secret_reply = GenServer.call(:server, {:secret_message, id, secret_message})
      reply = CP.decrypt(key, secret_reply)
      IO.puts "(client) received reply: " <> reply
      {:reply, reply, state}
    end
  end

  # Server mockup
  defmodule Server do
    use GenServer
    @timeout 10_000

    def start_link do
      GenServer.start_link(__MODULE__, [], name: :server)
    end

    @impl true
    def init(_), do: {:ok, CP.dh_pair()}

    @impl true
    def handle_call({:handshake, id, bP}, _from, state = {aS, aP}) do
      CP.register_key(id, CP.dh_key(bP, aS), @timeout)
      {:reply, aP, state}
    end

    @impl true
    def handle_call({:secret_message, id, secret_message}, _from, state) do
      IO.puts "(server) received encrypted message: " <> secret_message
      key = CP.get_key(id)
      message = CP.decrypt(key, secret_message)
      secret_reply = CP.encrypt(key, "ACK " <> message)
      # Optionally, prolong key
      CP.reset_timeout(id, @timeout)
      {:reply, secret_reply, state}
    end
  end

  test "send/receive encrypted message" do
    CP.start_link()
    {:ok, server_pid} = Server.start_link()
    {:ok, client_pid} = Client.start_link("user1")
    {:ok, key} = Client.handshake(client_pid)
    assert bit_size(key) == 256
    reply = Client.send_secret(client_pid, message = "attack at dawn")
    assert reply == "ACK " <> message
    GenServer.stop(client_pid)
    GenServer.stop(server_pid)
    CP.shutdown()
  end
end
