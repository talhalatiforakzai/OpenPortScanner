from app.api.utils import device_parser, port_parser
from app import db
from app.api.models import Devices
from app.celery.celery_app import celery
from app import create_app

app = create_app()


@celery.task(name="tasks.device_update")
def task_device_update(nmap_scan):
    with app.app_context():
        devices = device_parser(nmap_scan)
        for device in devices:
            if db.session.query(db.exists().where(Devices.ip == device.get('ip'))).scalar() or db.session.query(
                    db.exists().where(Devices.mac == device.get('mac'))).scalar():
                pass
            else:
                db.session.add(Devices(mac=device.get('mac', 'mac not found'), ip=device.get('ip', 'ip not found'),
                                       host=device.get('host', 'ip not found')))
        db.session.commit()


@celery.task(name="tasks.port_update")
def task_port_update(nmap_scan):
    with app.app_context():
        ports = port_parser(nmap_scan)
        for port in ports:
            tcp = ' '.join([str(elem) for elem in port.get('tcp')])
            udp = ' '.join([str(elem) for elem in port.get('udp')])
            ip = port.get('ip')
            db.session.query(Devices).filter_by(ip=ip).update(dict(tcp=tcp, udp=udp))
        db.session.commit()
