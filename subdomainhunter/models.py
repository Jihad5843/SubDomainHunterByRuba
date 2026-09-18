from dataclasses import dataclass, field, asdict
from typing import List, Optional

@dataclass
class Finding:
    hostname: str
    sources: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)
    cname: str = ""
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    http_url: str = ""
    https_url: str = ""
    title: str = ""
    technologies: List[str] = field(default_factory=list)
    content_type: str = ""
    server: str = ""
    redirect: str = ""
    wildcard: bool = False
    error: str = ""

    @property
    def resolved(self):
        return bool(self.addresses)

    @property
    def alive(self):
        return self.resolved or self.http_status is not None or self.https_status is not None

    @property
    def status(self):
        if self.https_status is not None:
            return self.https_status
        return self.http_status

    @property
    def live(self):
        return self.http_status is not None or self.https_status is not None

    def to_dict(self):
        d = asdict(self)
        d.update(resolved=self.resolved, alive=self.alive, live=self.live, status=self.status)
        return d
