"""Test package. Blocks all outbound network connections (rule: tests never
touch the network). Any attempt raises immediately and fails the test."""
import socket


def _blocked(*args, **kwargs):
    raise RuntimeError("network access is not allowed in tests")


socket.socket.connect = _blocked
socket.socket.connect_ex = _blocked
socket.create_connection = _blocked
