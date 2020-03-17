from functools import wraps
from lxml import etree
from flask import jsonify, request
from jsonschema import validate, ValidationError


def error_response(message):
    payload = {'error': message}
    response = jsonify(payload)
    return response


def bad_request(message):
    return error_response(400, message)


def validate_schema(schema):
    def wrapper(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            input = request.get_json(force=True)
            if not input:
                return error_response("data not found")
            try:
                validate(instance=input, schema=schema)
            except ValidationError as e:
                errors = e.message
                if errors:
                    response = jsonify(dict(success=False,
                                        message="Example input { 'ip_address':'192.168.100.0/24' }",
                                        errors=errors))
                    response.status_code = 406
                    return response
            else:
                return fn(*args, **kwargs)

        return wrapped

    return wrapper


def validate_xml():

    def wrapper(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            errors = True
            input = request.files['file']
            xml_file = etree.parse(input)
            if input.filename == "port.xml":
                xml_validator = etree.XMLSchema(file="app/api/schema/port.xsd")
            elif input.filename == "device.xml":
                xml_validator = etree.XMLSchema(file="app/api/schema/device.xsd")
            if xml_validator.validate(xml_file):
                errors = False
            if errors:
                response = jsonify(dict(success=False,
                                        message="invalid xml file",
                                        errors=errors))
                response.status_code = 406
                return response
            else:
                return fn(*args, **kwargs)

        return wrapped

    return wrapper




