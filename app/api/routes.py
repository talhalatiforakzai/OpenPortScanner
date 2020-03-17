import xmltodict, time, os
from app import db
from flask import Flask, request, send_file, jsonify
from werkzeug.utils import secure_filename
from config import Config
from app.api import bp
from app.api.utils import device_parser, port_parser, SCRIPT_COMMANDS
from app.api.models import Devices
from app.api.errors import bad_request, validate_schema, validate_xml
from app.api.schema.json_schema import download_script

app = Flask(__name__)
app.config.from_object(Config)


@bp.route('/download-script', methods=['GET'])
@validate_schema(download_script)
def download_script():
    data = request.get_json()
    if 'ip_address' not in data:
        return bad_request('must include the default gateway of the network')
    ip_address = data["ip_address"]
    command = SCRIPT_COMMANDS.format(ip_address=ip_address)
    with open(os.path.join(app.config['UPLOAD_FOLDER'], "discover_device.sh"), 'w') as filehandle:
        for itm in command:
            filehandle.write('%s' % itm)
    while not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], "discover_device.sh")):
        time.sleep(1)
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], "discover_device.sh"), as_attachment=True)


@bp.route('/info', methods=['GET'])
def info():
    data = db.session.query(Devices).all()
    return jsonify({
       "data":[result.serialized for result in data]
    })


@bp.route('/port-scanner', methods=['POST'])
@validate_xml()
def port_scanner():
    file = request.files['file']
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename)))
    if file.filename == "device.xml":
        with open(os.path.join(app.config['UPLOAD_FOLDER'], "device.xml")) as raw_xml:
            nmap_scan = xmltodict.parse(raw_xml.read())

        devices = device_parser(nmap_scan)
        for device in devices:
            if db.session.query(db.exists().where(Devices.ip == device.get('ip'))).scalar() or db.session.query(db.exists().where(Devices.mac == device.get('mac'))).scalar():
                pass
            else:
                db.session.add(Devices(mac=device.get('mac', 'mac not found'), ip=device.get('ip', 'ip not found'),
                                      host=device.get('host', 'ip not found')))
        db.session.commit()
        return "okay"
    elif file.filename == "port.xml":
        with open(os.path.join(app.config['UPLOAD_FOLDER'], "port.xml")) as raw_xml:
            nmap_scan = xmltodict.parse(raw_xml.read())

        ports = port_parser(nmap_scan)
        for port in ports:
            tcp = ' '.join([str(elem) for elem in port.get('tcp')])
            udp = ' '.join([str(elem) for elem in port.get('udp')])
            db.session.query(Devices).filter_by(ip= port.get('ip')).update(dict(tcp=tcp,udp=udp))
        db.session.commit()
    return "okay"
