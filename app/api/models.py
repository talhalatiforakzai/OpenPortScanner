from app import db


class Devices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20), unique=True)
    ip = db.Column(db.String(15), unique=True)
    host = db.Column(db.String(60))
    tcp = db.Column(db.String(200))
    udp = db.Column(db.String(200))

    @property
    def serialized(self):
        return {
            'mac' : self.mac,
            'ip' : self.ip,
            'host' : self.host,
            'tcp' : self.tcp,
            'udp' : self.udp
        }