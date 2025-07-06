

def ensure_list(x):
    return x.apply(lambda lst: lst if isinstance(lst, list) else ["unknown"])

# Et si besoin :
def is_internal(ip: str) -> int:
    import ipaddress
    try:
        return int(ipaddress.ip_address(ip).is_private)
    except Exception:
        return 0

