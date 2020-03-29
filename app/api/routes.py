import prometheus_client
import xmltodict
from app import db
from flask import request, jsonify, Response
from app.api import bp
from app.api.utils import SCRIPT_COMMANDS
from app.api.models import Devices
from app.api.errors import bad_request, validate_schema, validate_xml
from app.api.schema.json_schema import download_script


@bp.route('/download-script', methods=['GET'])
@validate_schema(download_script)
def download_script():
    data = request.get_json()
    if 'ip_address' not in data:
        return bad_request('must include the default gateway of the network')
    ip_address = data["ip_address"]
    command = SCRIPT_COMMANDS.format(ip_address=ip_address)
    response = Response(command, mimetype='text/sh')
    response.headers.set("Content-Disposition", "attachment", filename="Open_Port_Scanner.sh")
    return response


@bp.route('/info', methods=['GET'])
def info():
    data = db.session.query(Devices).all()
    return jsonify({
       "data":[result.serialized for result in data]
    })


@bp.route('/port-scanner', methods=['POST'])
@validate_xml()
def port_scanner():
    from app.celery.celery_app import celery

    file = request.files['file']
    nmap_scan = xmltodict.parse(file.read())
    if file.filename == "port.xml":
        task = celery.send_task('tasks.port_update', args=[nmap_scan])
    elif file.filename == "device.xml":
        task = celery.send_task('tasks.device_update', args=[nmap_scan])

    return jsonify({"Task send to queue , your task id is " : task.id})