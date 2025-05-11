package main

import "core:bytes"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"

State :: struct {
	is_quit:             bool,
	is_msg_len_at_start: bool,
}

state_create :: proc() -> State {
	return State{is_quit = false}
}

state_check_for_cmd :: proc(state: ^State, cmd: []byte) -> bool {
	// ignoring "\n"
	cmd_str := string(cmd[:len(cmd) - 1])
	if (strings.compare("-qq", cmd_str) == 0 || strings.compare("-quit", cmd_str) == 0) {
		fmt.printfln("Quitting...")
		state.is_quit = true
		return true
	}

	// message size
	if (strings.compare("-ms", cmd_str) == 0) {
		if state.is_msg_len_at_start {
			fmt.printfln("Enabled i32 (4 bytes) represented length at the start of the message, including that length")
			state.is_msg_len_at_start = true
		} else {
            fmt.printfln("Disabled i32 represented length at the start of the message")
            state.is_msg_len_at_start = false
        }

		return true
	}

	return false
}

print_error_and_exit :: proc(msg: string, param: any) {
	fmt.eprintfln(msg, param)
	os.exit(1)
}

main :: proc() {
	if (len(os.args) < 3) {
		print_error_and_exit("Not enough arguments try: bs <host> <port>", nil)
	}

	builder: strings.Builder
	strings.builder_init(&builder)
	defer strings.builder_destroy(&builder)
	fmt.sbprintf(&builder, "%s:%s", os.args[1], os.args[2])
	connection_string := strings.to_string(builder)

	socket, socket_creation_err := net.dial_tcp_from_hostname_and_port_string(connection_string)
	net.set_blocking(socket, false)
	net.set_option(socket, net.Socket_Option.TCP_Nodelay, true)
	defer net.close(socket)

	if socket_creation_err != nil {
		print_error_and_exit("Error creating socket", socket_creation_err)
	}

	fmt.printfln("Successfully created socket: %d", socket)

	state := state_create()
	input_buf := make([]byte, 1024)

	for !state.is_quit {
		n, read_stdin_err := os.read(os.stdin, input_buf[:])

		if n == 0 {
			continue
		}

		if read_stdin_err != nil {
			print_error_and_exit("Cannot read input", read_stdin_err)
		}

		if state_check_for_cmd(&state, input_buf[:n]) {
			continue
		}

		msg_buf: []byte
		buffer: bytes.Buffer
		bytes.buffer_init(&buffer, msg_buf[:])
		defer bytes.buffer_destroy(&buffer)

		if state.is_msg_len_at_start {
			dummy_len := i32_to_bytes(1)
			bytes.buffer_write(&buffer, dummy_len[:])

			bytes.buffer_write(&buffer, input_buf[:])

			message_len_byte_slice_representation := i32_to_bytes(
				cast(i32)bytes.buffer_length(&buffer),
			)
			bytes.buffer_write_at(&buffer, message_len_byte_slice_representation[:], 0)
		} else {
			bytes.buffer_write(&buffer, input_buf[:])
		}

		msg_buf, _ = bytes.buffer_read_bytes(&buffer, '\n')
		fmt.printfln("Sending: %w", msg_buf)

		sended_bytes, send_error := net.send_tcp(socket, msg_buf)

		if send_error != nil {
			print_error_and_exit("Cannot send data to socket", send_error)
		}

		fmt.printfln("Successfully sended data to socket")
	}
}

i32_to_bytes :: proc(value: i32) -> [4]u8 {
	return [4]u8 {
		u8((value >> 24) & 0xFF),
		u8((value >> 16) & 0xFF),
		u8((value >> 8) & 0xFF),
		u8(value & 0xFF),
	}
}
