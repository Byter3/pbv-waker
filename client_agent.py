import psutil
import socket
import requests
import ctypes
import ctypes.wintypes
import logging

SERVER_URL = "http://10.10.101.130:5000/api/register"
TARGET_SUBNET_PREFIX = "10.10.101."

# Set up logging — console + file on C:\ drive (overwrites each run with latest report)
LOG_FILE = r"C:\ProgramData\pbv_agent.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8'),
    ]
)
log = logging.getLogger("PBV-Agent")


# ─── WTS (Windows Terminal Services) API via ctypes ────────────────────────
# This allows us to enumerate ALL logged-in user sessions from SYSTEM context,
# including console and RDP sessions, without requiring pywin32.

# WTS Session States
WTS_ACTIVE = 0
WTS_CONNECTED = 1
WTS_CONNECTQUERY = 2
WTS_SHADOW = 3
WTS_DISCONNECTED = 4
WTS_IDLE = 5

# WTS Info Classes
WTSUserName = 5
WTSWinStationName = 6
WTSClientProtocolType = 16
WTSSessionInfo = 24  # WTSINFO struct with idle time

WTS_CURRENT_SERVER_HANDLE = 0

# Session state names for filtering
ACTIVE_STATES = {WTS_ACTIVE, WTS_DISCONNECTED}


class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = [
        ("SessionId", ctypes.wintypes.DWORD),
        ("pWinStationName", ctypes.c_wchar_p),
        ("State", ctypes.wintypes.DWORD),
    ]


class LARGE_INTEGER(ctypes.Structure):
    """Windows LARGE_INTEGER / FILETIME as a 64-bit signed value."""
    _fields_ = [("QuadPart", ctypes.c_longlong)]


class WTSINFO(ctypes.Structure):
    """
    _WTSINFO structure returned by WTSQuerySessionInformation
    with WTSSessionInfo info class.
    Contains timing info including last input time.
    """
    _fields_ = [
        ("State", ctypes.wintypes.DWORD),
        ("SessionId", ctypes.wintypes.DWORD),
        ("IncomingBytes", ctypes.wintypes.DWORD),
        ("OutgoingBytes", ctypes.wintypes.DWORD),
        ("IncomingFrames", ctypes.wintypes.DWORD),
        ("OutgoingFrames", ctypes.wintypes.DWORD),
        ("IncomingCompressedBytes", ctypes.wintypes.DWORD),
        ("OutgoingCompressedBytes", ctypes.wintypes.DWORD),
        ("WinStationName", ctypes.c_wchar * 32),
        ("Domain", ctypes.c_wchar * 17),
        ("UserName", ctypes.c_wchar * 21),
        ("ConnectTime", LARGE_INTEGER),
        ("DisconnectTime", LARGE_INTEGER),
        ("LastInputTime", LARGE_INTEGER),
        ("LogonTime", LARGE_INTEGER),
        ("CurrentTime", LARGE_INTEGER),
    ]


wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# WTSEnumerateSessionsW
wtsapi32.WTSEnumerateSessionsW.argtypes = [
    ctypes.wintypes.HANDLE,  # hServer
    ctypes.wintypes.DWORD,   # Reserved
    ctypes.wintypes.DWORD,   # Version
    ctypes.POINTER(ctypes.POINTER(WTS_SESSION_INFO)),  # ppSessionInfo
    ctypes.POINTER(ctypes.wintypes.DWORD),  # pCount
]
wtsapi32.WTSEnumerateSessionsW.restype = ctypes.wintypes.BOOL

# WTSQuerySessionInformationW
wtsapi32.WTSQuerySessionInformationW.argtypes = [
    ctypes.wintypes.HANDLE,  # hServer
    ctypes.wintypes.DWORD,   # SessionId
    ctypes.wintypes.DWORD,   # WTSInfoClass
    ctypes.POINTER(ctypes.wintypes.LPWSTR),  # ppBuffer
    ctypes.POINTER(ctypes.wintypes.DWORD),   # pBytesReturned
]
wtsapi32.WTSQuerySessionInformationW.restype = ctypes.wintypes.BOOL

# WTSFreeMemory
wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]
wtsapi32.WTSFreeMemory.restype = None


def _query_session_string(session_id, info_class):
    """Query a string value from a WTS session."""
    buf = ctypes.wintypes.LPWSTR()
    size = ctypes.wintypes.DWORD()

    if wtsapi32.WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE, session_id, info_class,
        ctypes.byref(buf), ctypes.byref(size)
    ):
        value = buf.value or ""
        wtsapi32.WTSFreeMemory(buf)
        return value
    return ""


def _query_session_protocol(session_id):
    """
    Query the client protocol type for a session.
    Returns: 'console', 'rdp', or 'unknown'
    Protocol values: 0 = Console, 2 = RDP
    """
    buf = ctypes.wintypes.LPWSTR()
    size = ctypes.wintypes.DWORD()

    if wtsapi32.WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE, session_id, WTSClientProtocolType,
        ctypes.byref(buf), ctypes.byref(size)
    ):
        # Protocol is returned as a USHORT (2 bytes)
        proto = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ushort)).contents.value
        wtsapi32.WTSFreeMemory(buf)
        if proto == 0:
            return "console"
        elif proto == 2:
            return "rdp"
        else:
            return "unknown"
    return "unknown"


def _query_session_idle_seconds(session_id):
    """
    Query the idle time for a session using WTSINFO struct.
    Returns idle seconds as a float, or 0.0 on failure.
    """
    buf = ctypes.wintypes.LPWSTR()
    size = ctypes.wintypes.DWORD()

    if wtsapi32.WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE, session_id, WTSSessionInfo,
        ctypes.byref(buf), ctypes.byref(size)
    ):
        if size.value >= ctypes.sizeof(WTSINFO):
            info = ctypes.cast(buf, ctypes.POINTER(WTSINFO)).contents
            current_time = info.CurrentTime.QuadPart
            last_input = info.LastInputTime.QuadPart

            wtsapi32.WTSFreeMemory(buf)

            if last_input > 0 and current_time > last_input:
                # FILETIME is in 100-nanosecond intervals
                idle_seconds = (current_time - last_input) / 10_000_000.0
                return idle_seconds
            return 0.0
        wtsapi32.WTSFreeMemory(buf)
    return 0.0


def get_active_sessions():
    """
    Enumerate all active user sessions on this machine.
    Works from SYSTEM context — detects console, RDP, and disconnected sessions.

    Returns a list of dicts:
    [
        {"username": "gabor.abbas", "idle_seconds": 0.0, "session_type": "console"},
        {"username": "andras.foldvary", "idle_seconds": 300.0, "session_type": "rdp"},
    ]
    """
    sessions = []
    session_info_ptr = ctypes.POINTER(WTS_SESSION_INFO)()
    count = ctypes.wintypes.DWORD()

    if not wtsapi32.WTSEnumerateSessionsW(
        WTS_CURRENT_SERVER_HANDLE, 0, 1,
        ctypes.byref(session_info_ptr), ctypes.byref(count)
    ):
        log.error("WTSEnumerateSessionsW failed: %s", ctypes.get_last_error())
        return sessions

    try:
        for i in range(count.value):
            si = session_info_ptr[i]

            # Skip non-active sessions (only keep Active and Disconnected)
            if si.State not in ACTIVE_STATES:
                continue

            # Get username for this session
            username = _query_session_string(si.SessionId, WTSUserName)
            if not username:
                continue  # System sessions without a user

            # Get session type (console/rdp)
            session_type = _query_session_protocol(si.SessionId)

            # Mark disconnected sessions
            if si.State == WTS_DISCONNECTED:
                session_type = "disconnected"

            # Get idle time
            idle_seconds = _query_session_idle_seconds(si.SessionId)

            sessions.append({
                "username": username,
                "idle_seconds": round(idle_seconds, 1),
                "session_type": session_type,
            })

    finally:
        wtsapi32.WTSFreeMemory(session_info_ptr)

    return sessions


# ─── Network info (unchanged from original) ────────────────────────────────

def get_network_info():
    """
    Finds the interface with an IP in the 10.10.101.x range.
    Returns (hostname, ip, mac) or None if not found.
    """
    hostname = socket.gethostname()
    interfaces = psutil.net_if_addrs()

    for iface_name, addrs in interfaces.items():
        ip_address = None
        mac_address = None

        for addr in addrs:
            if addr.family == socket.AF_INET:
                if addr.address.startswith(TARGET_SUBNET_PREFIX):
                    ip_address = addr.address
            elif addr.family == psutil.AF_LINK:  # MAC address
                mac_address = addr.address.upper()

        if ip_address and mac_address:
            # Normalize MAC to AA:BB:CC... format (Windows uses - sometimes)
            mac_address = mac_address.replace('-', ':')
            return hostname, ip_address, mac_address

    return None


# ─── Registration ──────────────────────────────────────────────────────────

def register():
    info = get_network_info()
    if not info:
        log.warning("No network interface found with IP starting with %s", TARGET_SUBNET_PREFIX)
        return

    name, ip, mac = info
    active_users = get_active_sessions()

    payload = {
        "name": name,
        "ip": ip,
        "mac": mac,
        "active_users": active_users,
    }

    user_summary = ", ".join(
        f"{u['username']}({u['session_type']})" for u in active_users
    ) if active_users else "no users"

    log.info("Registering %s (%s) - %s | Users: %s", name, ip, mac, user_summary)

    try:
        response = requests.post(SERVER_URL, json=payload, timeout=15)
        if response.status_code == 200:
            log.info("Successfully registered!")
        else:
            log.error("Failed to register. Status: %d - %s", response.status_code, response.text)
    except Exception as e:
        log.error("Connection failed: %s", e)


if __name__ == "__main__":
    register()
