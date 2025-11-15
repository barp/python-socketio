import time
from unittest import mock


from socketio import packet
from socketio import server


@mock.patch('socketio.server.engineio.Server', **{
    'return_value.generate_id.side_effect': [str(i) for i in range(1, 100)]})
class TestRecovery:
    def test_recovery_enabled(self, eio):
        """Test that recovery is enabled when configured."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 3000})
        assert s.connection_state_recovery is not None
        cfg = s.connection_state_recovery
        assert cfg['max_disconnection_duration'] == 3000
        assert s.connection_state_recovery['skip_middlewares'] is True

    def test_recovery_disabled(self, eio):
        """Test that recovery is disabled by default."""
        s = server.Server()
        assert s.connection_state_recovery is None

    def test_basic_recovery(self, eio):
        """Test basic connection recovery."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 120000})
        s._generate_pid = lambda: 'pid123456'
        s.manager.initialize = mock.MagicMock()

        # Connect
        s._handle_eio_connect('eio123', {})
        connect_pkt = packet.Packet(packet.CONNECT, namespace='/', data={})
        s._handle_eio_message('eio123', connect_pkt.encode())

        # Verify connection
        sid = '1'  # First generated ID
        assert s.manager.is_connected(sid, '/')
        assert sid in s._sid_to_pid
        pid = s._sid_to_pid[sid]

        # Disconnect
        s._handle_eio_disconnect('eio123', 'transport close')
        assert not s.manager.is_connected(sid, '/')

        # Verify recovery state stored
        assert pid in s._recovery_sessions
        assert '/' in s._recovery_sessions[pid]
        recovery = s._recovery_sessions[pid]['/']
        assert recovery['sid'] == sid

        # Reconnect with pid
        s._handle_eio_connect('eio456', {})
        reconnect_pkt = packet.Packet(
            packet.CONNECT, namespace='/', data={'pid': pid})
        s._handle_eio_message('eio456', reconnect_pkt.encode())

        # Verify recovery
        assert s.manager.is_connected(sid, '/')
        # Should be removed after recovery
        assert pid not in s._recovery_sessions

    def test_recovery_with_rooms(self, eio):
        """Test recovery restores room membership."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 120000})
        s._generate_pid = lambda: 'pid123456'
        s.manager.initialize = mock.MagicMock()

        # Connect and join room
        s._handle_eio_connect('eio123', {})
        connect_pkt = packet.Packet(packet.CONNECT, namespace='/', data={})
        s._handle_eio_message('eio123', connect_pkt.encode())
        sid = '1'
        s.enter_room(sid, 'room1')
        s.enter_room(sid, 'room2')

        assert 'room1' in s.manager.get_rooms(sid, '/')
        assert 'room2' in s.manager.get_rooms(sid, '/')

        # Get pid before disconnect (it gets deleted during disconnect)
        pid = s._sid_to_pid.get(sid)
        assert pid is not None

        # Disconnect
        s._handle_eio_disconnect('eio123', 'transport close')

        # Reconnect
        s._handle_eio_connect('eio456', {})
        reconnect_pkt = packet.Packet(
            packet.CONNECT, namespace='/', data={'pid': pid})
        s._handle_eio_message('eio456', reconnect_pkt.encode())

        # Verify rooms restored
        rooms = s.manager.get_rooms(sid, '/')
        assert 'room1' in rooms
        assert 'room2' in rooms

    def test_recovery_with_session_data(self, eio):
        """Test recovery restores session data."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 120000})
        s._generate_pid = lambda: 'pid123456'
        s.manager.initialize = mock.MagicMock()

        # Mock session storage
        fake_sessions = {}

        def fake_get_session(eio_sid):
            if eio_sid not in fake_sessions:
                fake_sessions[eio_sid] = {}
            return fake_sessions[eio_sid]

        def fake_save_session(eio_sid, session):
            fake_sessions[eio_sid] = session

        s.eio.get_session = fake_get_session
        s.eio.save_session = fake_save_session

        # Connect and set session data
        s._handle_eio_connect('eio123', {})
        connect_pkt = packet.Packet(packet.CONNECT, namespace='/', data={})
        s._handle_eio_message('eio123', connect_pkt.encode())
        sid = '1'

        # Ensure eio_sid is in environ for recovery state storage
        assert 'eio123' in s.environ

        with s.session(sid) as session:
            session['user_id'] = 'user123'
            session['username'] = 'testuser'

        # Verify session was saved
        eio_sid = s.manager.eio_sid_from_sid(sid, '/')
        assert eio_sid == 'eio123'
        saved_session = fake_sessions.get(eio_sid, {})
        assert saved_session.get('/', {}).get('user_id') == 'user123'

        # Get pid before disconnect (it gets deleted during disconnect)
        pid = s._sid_to_pid.get(sid)
        assert pid is not None

        # Disconnect
        s._handle_eio_disconnect('eio123', 'transport close')

        # Reconnect
        s._handle_eio_connect('eio456', {})
        reconnect_pkt = packet.Packet(
            packet.CONNECT, namespace='/', data={'pid': pid})
        s._handle_eio_message('eio456', reconnect_pkt.encode())

        # Verify session data restored
        # After reconnection, eio_sid changes, get it from manager
        eio_sid_after_reconnect = s.manager.eio_sid_from_sid(sid, '/')
        assert eio_sid_after_reconnect is not None

        # Check that session data was restored to the new eio_sid
        restored_session = fake_sessions.get(eio_sid_after_reconnect, {})
        namespace_session = restored_session.get('/', {})
        assert namespace_session.get('user_id') == 'user123'
        assert namespace_session.get('username') == 'testuser'

        # Also verify via get_session
        session = s.get_session(sid)
        assert session.get('user_id') == 'user123'
        assert session.get('username') == 'testuser'

    def test_recovery_expired(self, eio):
        """Test that expired recovery sessions are not restored."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 100})
        s._generate_pid = lambda: 'pid123456'
        s.manager.initialize = mock.MagicMock()

        # Connect and disconnect
        s._handle_eio_connect('eio123', {})
        connect_pkt = packet.Packet(packet.CONNECT, namespace='/', data={})
        s._handle_eio_message('eio123', connect_pkt.encode())
        sid = '1'
        pid = s._sid_to_pid[sid]

        s._handle_eio_disconnect('eio123', 'transport close')

        # Wait for expiration
        time.sleep(0.2)  # Wait longer than max_disconnection_duration (100ms)

        # Try to reconnect
        s._handle_eio_connect('eio456', {})
        reconnect_pkt = packet.Packet(
            packet.CONNECT, namespace='/', data={'pid': pid})
        s._handle_eio_message('eio456', reconnect_pkt.encode())

        # Should create new connection, not recover old one
        # New sid will be different (should be '2' since we used '1')
        new_sid = s.manager.sid_from_eio_sid('eio456', '/')
        assert new_sid != sid

    def test_recovery_invalid_pid(self, eio):
        """Test that invalid pid doesn't cause errors."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 120000})
        s._generate_pid = lambda: 'pid123456'
        s.manager.initialize = mock.MagicMock()

        # Try to reconnect with invalid pid
        s._handle_eio_connect('eio123', {})
        reconnect_pkt = packet.Packet(
            packet.CONNECT, namespace='/', data={'pid': 'invalid'})
        s._handle_eio_message('eio123', reconnect_pkt.encode())

        # Should create new connection
        assert s.manager.is_connected('1', '/')

    def test_pid_in_connect_response(self, eio):
        """Test pid included in CONNECT response when recovery enabled."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 120000})
        s._generate_pid = lambda: 'pid123456'
        s.manager.initialize = mock.MagicMock()

        # Connect
        s._handle_eio_connect('eio123', {})
        connect_pkt = packet.Packet(packet.CONNECT, namespace='/', data={})

        # Capture sent packets
        sent_packets = []
        original_send = s.eio.send

        def mock_send(eio_sid, data):
            sent_packets.append(data)
            return original_send(eio_sid, data)
        s.eio.send = mock_send

        s._handle_eio_message('eio123', connect_pkt.encode())

        # Check that CONNECT packet includes pid
        connect_responses = [p for p in sent_packets if p.startswith('0')]
        assert len(connect_responses) > 0
        if connect_responses:
            # Parse: '0{"sid":"1","pid":"pid123456"}'
            assert 'pid' in connect_responses[0]

    def test_offset_in_packets(self, eio):
        """Test offsets added to EVENT packets when recovery enabled."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 120000})
        s._generate_pid = lambda: 'pid123456'
        s._generate_offset = lambda: 'offset1'
        s.manager.initialize = mock.MagicMock()

        # Connect
        s._handle_eio_connect('eio123', {})
        connect_pkt = packet.Packet(packet.CONNECT, namespace='/', data={})
        s._handle_eio_message('eio123', connect_pkt.encode())
        eio_sid = 'eio123'

        # Send an event
        event_pkt = packet.Packet(
            packet.EVENT, namespace='/', data=['test_event', 'data'])

        # Capture sent packets to check offset
        sent_packets = []
        original_send = s.eio.send

        def mock_send(eio_sid_param, data):
            sent_packets.append(data)
            return original_send(eio_sid_param, data)
        s.eio.send = mock_send

        s._send_packet(eio_sid, event_pkt)

        # Verify offset was added - the packet should end with the offset
        # Format: '2["test_event","data","offset1"]'
        assert len(sent_packets) > 0
        event_packets = [p for p in sent_packets if p.startswith('2')]
        if event_packets:
            # Check that offset is in the packet
            assert 'offset1' in event_packets[0]

    def test_no_recovery_on_server_disconnect(self, eio):
        """Test recovery not stored on server-initiated disconnect."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 120000})
        s._generate_pid = lambda: 'pid123456'
        s.manager.initialize = mock.MagicMock()

        # Connect
        s._handle_eio_connect('eio123', {})
        connect_pkt = packet.Packet(packet.CONNECT, namespace='/', data={})
        s._handle_eio_message('eio123', connect_pkt.encode())
        sid = '1'
        pid = s._sid_to_pid[sid]

        # Server disconnect
        s.disconnect(sid)

        # Recovery state should not be stored
        assert pid not in s._recovery_sessions

    def test_skip_middlewares_on_recovery(self, eio):
        """Test that connect handler is skipped on successful recovery."""
        s = server.Server(connection_state_recovery={
                          'max_disconnection_duration': 120000})
        s._generate_pid = lambda: 'pid123456'
        s.manager.initialize = mock.MagicMock()

        # Connect
        s._handle_eio_connect('eio123', {})
        connect_pkt = packet.Packet(packet.CONNECT, namespace='/', data={})
        s._handle_eio_message('eio123', connect_pkt.encode())
        sid = '1'
        pid = s._sid_to_pid[sid]

        # Disconnect
        s._handle_eio_disconnect('eio123', 'transport close')

        # Track connect handler calls
        connect_calls = []

        @s.on('connect')
        def connect_handler(sid_param, environ):
            connect_calls.append(sid_param)
            return True

        # Reconnect
        s._handle_eio_connect('eio456', {})
        reconnect_pkt = packet.Packet(
            packet.CONNECT, namespace='/', data={'pid': pid})
        s._handle_eio_message('eio456', reconnect_pkt.encode())

        # Connect handler should not be called
        # (skip_middlewares True by default)
        assert len(connect_calls) == 0
