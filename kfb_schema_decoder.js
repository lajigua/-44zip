'use strict';

const fs = require('node:fs');
const path = require('node:path');

const WIRE_NAMES = ['Variant', 'Fixed32', 'Fixed64', 'Object', 'String', 'List', 'Dictionary', 'Packed'];
const SIGNED_TYPES = new Set(['System.SByte', 'System.Int16', 'System.Int32', 'System.Int64']);
const UNSIGNED_TYPES = new Set(['System.Byte', 'System.UInt16', 'System.UInt32', 'System.UInt64', 'System.Char']);

class DecodeError extends Error {
  constructor(message, offset, objectPath = '') {
    super(`${message} at offset ${offset}${objectPath ? ` (${objectPath})` : ''}`);
    this.name = 'KfbDecodeError';
    this.offset = offset;
    this.objectPath = objectPath;
  }
}

function cloneJson(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function parseDefaultJson(value) {
  if (value === undefined || value === null) return {};
  if (typeof value === 'object') return cloneJson(value);
  if (typeof value !== 'string' || value.trim() === '') return {};
  try { return JSON.parse(value); } catch (_) { return {}; }
}

function normalizeSchema(raw) {
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.types)) {
    throw new Error('KFB schema must contain a types array');
  }
  const schema = {
    raw,
    rootType: raw.root_type || 'KH.ActorData',
    polymorphicTypeField: raw.polymorphic_type_field || '$type',
    typesByName: new Map(),
    typesById: new Map(),
    customTypes: new Map(),
  };
  for (const entry of raw.custom_serializers || []) {
    const name = entry.type || entry.full_name;
    if (name) schema.customTypes.set(name, entry);
  }
  for (const entry of raw.types) {
    const fullName = entry.full_name || entry.name;
    if (!fullName) continue;
    const type = {
      ...entry,
      fullName,
      typeId: entry.type_id === undefined || entry.type_id === null ? null : Number(entry.type_id),
      baseType: entry.base_type || null,
      fields: Array.isArray(entry.fields) ? entry.fields.map((field) => ({
        ...field,
        tag: Number(field.tag),
        name: field.name || `field_${field.tag}`,
        fieldType: field.field_type || field.declared_type || 'System.Object',
        declaredBy: field.declared_by || fullName,
        displayType: field.display_type || null,
        editableName: field.editable_name || null,
      })) : [],
      defaultValue: parseDefaultJson(entry.default_json),
    };
    schema.typesByName.set(fullName, type);
    if (type.typeId !== null && Number.isInteger(type.typeId)) schema.typesById.set(type.typeId, type);
  }
  if (!schema.typesByName.has(schema.rootType)) {
    throw new Error(`schema does not contain root type ${schema.rootType}`);
  }
  return schema;
}

function loadSchema(schemaPath, defaultPath) {
  let selected = schemaPath ? path.resolve(schemaPath) : null;
  if (!selected && defaultPath && fs.existsSync(defaultPath)) selected = path.resolve(defaultPath);
  if (!selected) throw new Error('no ActorData schema is installed; export KFB rules once and pass --schema <kfb_schema.json>');
  const text = fs.readFileSync(selected, 'utf8').replace(/^\uFEFF/, '');
  return { path: selected, schema: normalizeSchema(JSON.parse(text)) };
}

class Reader {
  constructor(buffer, start = 0, end = buffer.length, coverage = null, objectPath = '$') {
    this.buffer = buffer;
    this.position = start;
    this.start = start;
    this.end = end;
    this.coverage = coverage || [];
    this.objectPath = objectPath;
  }

  error(message, offset = this.position) { throw new DecodeError(message, offset, this.objectPath); }
  remaining() { return this.end - this.position; }
  ensure(count, what) {
    if (!Number.isInteger(count) || count < 0 || this.position + count > this.end) {
      this.error(`truncated ${what}`);
    }
  }
  mark(start, kind, detail = '') {
    this.coverage.push({ start, end: this.position, kind, path: this.objectPath, detail });
  }
  readByte(kind = 'byte') {
    this.ensure(1, kind);
    const start = this.position;
    const value = this.buffer[this.position++];
    this.mark(start, kind);
    return value;
  }
  peekByte() { this.ensure(1, 'byte'); return this.buffer[this.position]; }
  readBytes(count, kind = 'bytes') {
    this.ensure(count, kind);
    const start = this.position;
    const result = this.buffer.subarray(this.position, this.position + count);
    this.position += count;
    this.mark(start, kind, String(count));
    return result;
  }
  readVarint(kind = 'varint') {
    const start = this.position;
    let value = 0n;
    let shift = 0n;
    while (this.position < this.end && shift <= 63n) {
      const byte = this.buffer[this.position++];
      value |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        this.mark(start, kind, value.toString());
        return value;
      }
      shift += 7n;
    }
    this.error(`truncated or oversized ${kind}`, start);
  }
  readLength(kind = 'length') {
    const value = this.readVarint(kind);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) this.error(`${kind} is too large`);
    const number = Number(value);
    if (number > this.remaining()) this.error(`${kind} ${number} exceeds enclosing block`);
    return number;
  }
  subReader(length, objectPath) {
    this.ensure(length, 'subitem');
    const result = new Reader(this.buffer, this.position, this.position + length, this.coverage, objectPath);
    this.position += length;
    return result;
  }
}

function zigZag(value) { return (value >> 1n) ^ (-(value & 1n)); }
function safeIntegerOrString(value, forceString = false) {
  if (forceString || value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) {
    return value.toString();
  }
  return Number(value);
}
function typeCode(field) { return field.type_code || field.typeCode || ''; }
function isSigned(field, declaredType = field.fieldType) {
  if (field.is_enum) {
    return ['SByte', 'Int16', 'Int32', 'Int64'].includes(field.enum_underlying_type_code);
  }
  return SIGNED_TYPES.has(declaredType) || ['SByte', 'Int16', 'Int32', 'Int64'].includes(typeCode(field));
}
function isUnsigned(field, declaredType = field.fieldType) {
  if (field.is_enum) {
    return ['Byte', 'UInt16', 'UInt32', 'UInt64', 'Char'].includes(field.enum_underlying_type_code);
  }
  return UNSIGNED_TYPES.has(declaredType) || ['Byte', 'UInt16', 'UInt32', 'UInt64', 'Char'].includes(typeCode(field));
}
function isBoolean(field, declaredType = field.fieldType) {
  return declaredType === 'System.Boolean' || typeCode(field) === 'Boolean';
}
function isString(field, declaredType = field.fieldType) {
  return declaredType === 'System.String' || typeCode(field) === 'String';
}
function isFloat(field, declaredType = field.fieldType) {
  return declaredType === 'System.Single' || typeCode(field) === 'Single';
}
function isDouble(field, declaredType = field.fieldType) {
  return declaredType === 'System.Double' || typeCode(field) === 'Double';
}

function firstGenericTypeArgument(typeName) {
  const start = String(typeName).indexOf('[[');
  if (start < 0) return null;
  const text = String(typeName);
  let depth = 0;
  for (let index = start + 2; index < text.length; index += 1) {
    const char = text[index];
    if (char === '[') depth += 1;
    else if (char === ']') {
      if (depth === 0) return text.slice(start + 2, index).trim();
      depth -= 1;
    } else if (char === ',' && depth === 0) {
      return text.slice(start + 2, index).trim();
    }
  }
  return null;
}

function isListType(typeName) {
  return String(typeName).startsWith('System.Collections.Generic.List`1[[');
}

function makeScalar(value, scalarType, offset, endOffset) {
  return { semantic: value, ast: { kind: 'scalar', scalarType, value, offset, endOffset } };
}

function fieldCandidates(schema, type, tag) {
  const candidates = [];
  let current = type;
  const visited = new Set();
  while (current && !visited.has(current.fullName)) {
    visited.add(current.fullName);
    for (const field of current.fields) if (field.tag === tag) candidates.push(field);
    current = current.baseType ? schema.typesByName.get(current.baseType) : null;
  }
  return candidates;
}

function chooseField(schema, type, tag, declaringType) {
  const candidates = fieldCandidates(schema, type, tag);
  if (candidates.length === 0) return null;
  return candidates.find((field) => field.declaredBy === declaringType) || candidates[0];
}

function editableFieldName(type, field) {
  if (field.editableName) return field.editableName;
  const duplicates = type.fields.filter((candidate) => candidate.name === field.name);
  if (duplicates.length <= 1) return field.name;
  const declaring = String(field.declaredBy || type.fullName).split('.').pop();
  return `${declaring}.${field.name}`;
}

function customLayout(typeName) {
  const layouts = {
    // LockStep JSON serializers expose the exact signed 32.32 raw value, not
    // a floating-point conversion.  This preserves values such as 2^53+1.
    'Morefun.LockStep.FScalar': { components: ['value'], encoding: 'sint64', json: 'scalar' },
    'KH.FVector2': { components: ['x', 'y'], encoding: 'sint64', json: 'csv' },
    'KH.FVector3': { components: ['x', 'y', 'z'], encoding: 'sint64', json: 'csv' },
    'KH.FVector4': { components: ['x', 'y', 'z', 'w'], encoding: 'sint64', json: 'csv' },
    'KH.FQuaternion': { components: ['x', 'y', 'z', 'w'], encoding: 'sint64', json: 'csv' },
    'KH.FColor': { components: ['r', 'g', 'b', 'a'], encoding: 'sint64', json: 'csv' },
    'KH.TSKFLFloatArg': { components: [
      { name: 'source', encoding: 'sint32' },
      { name: 'variable', encoding: 'string' },
      { name: 'value', encoding: 'sint64' },
    ], json: 'csv' },
    'KH.TSKFLIntArg': { components: [
      { name: 'source', encoding: 'sint32' },
      { name: 'variable', encoding: 'string' },
      { name: 'value', encoding: 'sint32' },
    ], json: 'csv' },
    'KH.TSKFLStringArg': { components: [
      { name: 'source', encoding: 'sint32' },
      { name: 'variable', encoding: 'string' },
      { name: 'value', encoding: 'string' },
    ], json: 'csv' },
    'UnityEngine.Vector2': { components: ['x', 'y'], encoding: 'float32', json: 'csv' },
    'UnityEngine.Vector3': { components: ['x', 'y', 'z'], encoding: 'float32', json: 'csv' },
    'UnityEngine.Vector4': { components: ['x', 'y', 'z', 'w'], encoding: 'float32', json: 'csv' },
    'UnityEngine.Vector3Int': { components: ['x', 'y', 'z'], encoding: 'sint32', json: 'csv' },
    'UnityEngine.Quaternion': { components: ['x', 'y', 'z', 'w'], encoding: 'float32', json: 'csv' },
    'UnityEngine.Rect': { components: ['x', 'y', 'width', 'height'], encoding: 'float32', json: 'csv' },
    'UnityEngine.Bounds': { components: ['cx', 'cy', 'cz', 'ex', 'ey', 'ez'], encoding: 'float32', json: 'csv' },
    'UnityEngine.Color': { components: ['r', 'g', 'b', 'a'], encoding: 'float32', json: 'csv' },
    'UnityEngine.Color32': { components: ['r', 'g', 'b', 'a'], encoding: 'byte', json: 'csv' },
  };
  return layouts[typeName] || null;
}

function fixedToText(raw) {
  const negative = raw < 0n;
  let absolute = negative ? -raw : raw;
  const integer = absolute >> 32n;
  const fractionRaw = absolute & 0xffffffffn;
  if (fractionRaw === 0n) return `${negative ? '-' : ''}${integer}`;
  let fraction = ((fractionRaw * 10000000000n) >> 32n).toString().padStart(10, '0').replace(/0+$/, '');
  return `${negative ? '-' : ''}${integer}.${fraction}`;
}

function formatSingle(value) {
  if (!Number.isFinite(value)) return String(value);
  if (Object.is(value, -0)) return '0';
  const text = value.toPrecision(9);
  const parts = text.split(/e/i);
  let mantissa = parts[0];
  if (mantissa.includes('.')) mantissa = mantissa.replace(/0+$/, '').replace(/\.$/, '');
  return parts.length === 2 ? `${mantissa}E${Number(parts[1])}` : mantissa;
}

function decodeUnityAnimationCurve(reader, typeName) {
  const start = reader.position;
  const preWrapMode = zigZag(reader.readVarint('curve-pre-wrap'));
  const postWrapMode = zigZag(reader.readVarint('curve-post-wrap'));
  const countBig = zigZag(reader.readVarint('curve-key-count'));
  if (countBig < 0n || countBig > 1000000n) reader.error(`invalid AnimationCurve key count ${countBig}`, start);
  const count = Number(countBig);
  const keys = [];
  for (let index = 0; index < count; index += 1) {
    const values = [];
    for (let component = 0; component < 6; component += 1) {
      values.push(formatSingle(reader.readBytes(4, 'curve-float32').readFloatLE(0)));
    }
    values.push(zigZag(reader.readVarint('curve-weighted-mode')).toString());
    keys.push(values);
  }
  const semantic = [preWrapMode.toString(), postWrapMode.toString(), String(count),
    ...keys.map((values) => values.join(','))].join('|');
  return {
    semantic,
    ast: {
      kind: 'custom', type: typeName, value: semantic,
      components: { preWrapMode: preWrapMode.toString(), postWrapMode: postWrapMode.toString(), keys },
      offset: start, endOffset: reader.position,
    },
  };
}

function decodeCustom(reader, typeName) {
  if (typeName === 'UnityEngine.AnimationCurve') return decodeUnityAnimationCurve(reader, typeName);
  const layout = customLayout(typeName);
  if (!layout) reader.error(`unknown custom serializer ${typeName}`);
  const start = reader.position;
  const components = {};
  for (const component of layout.components) {
    const name = typeof component === 'string' ? component : component.name;
    const encoding = typeof component === 'string' ? layout.encoding : component.encoding;
    if (encoding === 'sint64' || encoding === 'sint32') {
      components[name] = zigZag(reader.readVarint(`custom-${encoding}`));
    } else if (encoding === 'uint64' || encoding === 'uint32') {
      components[name] = reader.readVarint(`custom-${encoding}`);
    } else if (encoding === 'string') {
      const length = reader.readLength('custom-string-length');
      components[name] = reader.readBytes(length, 'custom-utf8').toString('utf8');
    } else if (encoding === 'float32') {
      const bytes = reader.readBytes(4, 'custom-fixed32');
      components[name] = formatSingle(bytes.readFloatLE(0));
    } else if (encoding === 'float64') {
      const bytes = reader.readBytes(8, 'custom-fixed64');
      components[name] = bytes.readDoubleLE(0);
    } else if (encoding === 'byte') components[name] = reader.readByte('custom-byte');
    else reader.error(`unsupported custom component encoding ${encoding}`);
  }
  const strings = layout.components.map((component) => {
    const name = typeof component === 'string' ? component : component.name;
    return String(components[name]);
  });
  const semantic = layout.json === 'scalar' ? strings[0] : strings.join(',');
  return {
    semantic,
    ast: {
      kind: 'custom', type: typeName, value: semantic,
      components: Object.fromEntries(Object.entries(components).map(([key, value]) =>
        [key, typeof value === 'bigint' ? value.toString() : value])),
      offset: start, endOffset: reader.position,
    },
  };
}

function decodePrimitiveRaw(reader, field, declaredType) {
  const start = reader.position;
  if (isString(field, declaredType)) {
    const length = reader.readLength('string-length');
    const bytes = reader.readBytes(length, 'utf8');
    const value = bytes.toString('utf8');
    if (Buffer.from(value, 'utf8').length !== bytes.length) reader.error('invalid UTF-8 string', start);
    return { semantic: value, ast: { kind: 'string', value, offset: start, endOffset: reader.position } };
  }
  if (isFloat(field, declaredType)) {
    const bytes = reader.readBytes(4, 'fixed32');
    return makeScalar(Number(formatSingle(bytes.readFloatLE(0))), 'Single', start, reader.position);
  }
  if (isDouble(field, declaredType)) {
    const bytes = reader.readBytes(8, 'fixed64');
    return makeScalar(bytes.readDoubleLE(0), 'Double', start, reader.position);
  }
  const encoded = reader.readVarint(isSigned(field, declaredType) ? 'zigzag' : 'variant');
  const decoded = isSigned(field, declaredType) ? zigZag(encoded) : encoded;
  if (isBoolean(field, declaredType)) {
    if (decoded !== 0n && decoded !== 1n) reader.error(`invalid Boolean value ${decoded}`, start);
    return makeScalar(decoded === 1n, 'Boolean', start, reader.position);
  }
  const is64 = declaredType === 'System.Int64' || declaredType === 'System.UInt64' ||
    typeCode(field) === 'Int64' || typeCode(field) === 'UInt64';
  return makeScalar(safeIntegerOrString(decoded, is64), field.is_enum ? declaredType : typeCode(field) || declaredType,
    start, reader.position);
}

function decodeDeclaredItem(reader, field, declaredType, schema, objectPath) {
  if (schema.customTypes.has(declaredType) || field.has_custom_serializer) {
    const markerOffset = reader.position;
    const marker = reader.readByte('item-wire');
    if (marker === 0) return { semantic: null, ast: { kind: 'null', offset: markerOffset, endOffset: reader.position } };
    if (marker !== 3) reader.error(`custom item ${declaredType} uses wire ${marker}, expected Object`, markerOffset);
    const length = reader.readLength('item-length');
    const sub = reader.subReader(length, objectPath);
    const result = decodeCustom(sub, declaredType);
    if (sub.remaining() !== 0) sub.error(`custom serializer ${declaredType} left ${sub.remaining()} bytes`);
    return result;
  }
  if (isString(field, declaredType) || isBoolean(field, declaredType) || isSigned(field, declaredType) ||
      isUnsigned(field, declaredType) || isFloat(field, declaredType) || isDouble(field, declaredType) || field.is_enum) {
    return decodePrimitiveRaw(reader, field, declaredType);
  }
  if (isListType(declaredType)) {
    const markerOffset = reader.position;
    const marker = reader.readByte('item-wire');
    if (marker === 0) return { semantic: null, ast: { kind: 'null', offset: markerOffset, endOffset: reader.position } };
    if (marker !== 5) reader.error(`nested List item uses wire ${marker}, expected List`, markerOffset);
    const elementType = firstGenericTypeArgument(declaredType);
    if (!elementType) reader.error(`cannot determine nested List element type ${declaredType}`, markerOffset);
    return decodeCollection(reader, {
      name: 'Item', fieldType: declaredType, is_list: true, is_array: false, is_dictionary: false,
      element_type: elementType,
    }, schema, objectPath);
  }
  if (schema.typesByName.has(declaredType) || field.is_kfb_serializable || field.polymorphic) {
    const markerOffset = reader.position;
    const marker = reader.readByte('item-wire');
    if (marker === 0) return { semantic: null, ast: { kind: 'null', offset: markerOffset, endOffset: reader.position } };
    if (marker !== 3) reader.error(`object item ${declaredType} uses wire ${marker}, expected Object`, markerOffset);
    const length = reader.readLength('item-length');
    const sub = reader.subReader(length, objectPath);
    return decodeObjectPayload(sub, declaredType, schema, objectPath, true);
  }
  reader.error(`unsupported declared collection item type ${declaredType}`);
}

function decodeCollection(reader, field, schema, objectPath) {
  const start = reader.position;
  const countBig = reader.readVarint('collection-count');
  if (countBig > 10000000n) reader.error(`unreasonable collection count ${countBig}`, start);
  const count = Number(countBig);
  if (field.is_dictionary) {
    const entries = [];
    const semantic = {};
    for (let index = 0; index < count; index += 1) {
      const keyField = { fieldType: field.key_type, type_code: '', is_enum: false };
      const key = decodeDeclaredItem(reader, keyField, field.key_type, schema, `${objectPath}[${index}].Key`);
      const valueField = { ...field, fieldType: field.value_type, is_dictionary: false, is_list: false, is_array: false,
        has_custom_serializer: schema.customTypes.has(field.value_type),
        is_kfb_serializable: schema.typesByName.has(field.value_type) };
      const value = decodeDeclaredItem(reader, valueField, field.value_type, schema, `${objectPath}[${index}].Value`);
      const property = typeof key.semantic === 'string' ? key.semantic : String(key.semantic);
      if (Object.prototype.hasOwnProperty.call(semantic, property)) reader.error(`duplicate Dictionary key ${property}`);
      semantic[property] = value.semantic;
      entries.push({ key: key.ast, value: value.ast, index });
    }
    return { semantic, ast: { kind: 'dictionary', entries, offset: start, endOffset: reader.position } };
  }
  const elementType = field.element_type;
  if (!elementType) reader.error(`collection field ${field.name} lacks element_type`, start);
  const items = [];
  const semantic = [];
  for (let index = 0; index < count; index += 1) {
    const elementField = { ...field, fieldType: elementType, is_dictionary: false, is_list: false, is_array: false,
      has_custom_serializer: schema.customTypes.has(elementType),
      is_kfb_serializable: schema.typesByName.has(elementType) };
    const item = decodeDeclaredItem(reader, elementField, elementType, schema, `${objectPath}[${index}]`);
    items.push({ ...item.ast, index });
    semantic.push(item.semantic);
  }
  return { semantic, ast: { kind: field.is_array ? 'array' : 'list', items, offset: start, endOffset: reader.position } };
}

function decodePacked(reader, field, schema, objectPath) {
  const start = reader.position;
  const length = reader.readLength('packed-length');
  const packed = reader.subReader(length, objectPath);
  const elementType = field.element_type;
  if (!elementType) packed.error(`packed field ${field.name} lacks element_type`);
  const items = [];
  const semantic = [];
  while (packed.remaining() > 0) {
    const elementField = { ...field, fieldType: elementType, is_array: false, is_list: false, is_dictionary: false };
    const item = decodePrimitiveRaw(packed, elementField, elementType);
    items.push({ ...item.ast, index: items.length });
    semantic.push(item.semantic);
  }
  return { semantic, ast: { kind: 'array', packed: true, items, offset: start, endOffset: reader.position } };
}

function decodeFieldValue(reader, wire, field, schema, objectPath) {
  const start = reader.position;
  if (field.is_dictionary || wire === 6) {
    if (wire !== 6) reader.error(`field ${field.name} expected Dictionary wire, got ${WIRE_NAMES[wire]}`, start);
    return decodeCollection(reader, field, schema, objectPath);
  }
  if (field.is_list || (field.is_array && wire === 5) || wire === 5) {
    if (wire !== 5) reader.error(`field ${field.name} expected List wire, got ${WIRE_NAMES[wire]}`, start);
    return decodeCollection(reader, field, schema, objectPath);
  }
  if (wire === 7) return decodePacked(reader, field, schema, objectPath);
  if (schema.customTypes.has(field.fieldType) || field.has_custom_serializer) {
    if (wire !== 3) reader.error(`custom field ${field.name} expected Object wire, got ${WIRE_NAMES[wire]}`, start);
    const length = reader.readLength('object-length');
    const sub = reader.subReader(length, objectPath);
    let result;
    try {
      result = decodeCustom(sub, field.fieldType);
    } catch (error) {
      if (schema.lenientUnknown) {
        schema.unknownFields.push({
          type: field.fieldType, declaringType: field.declaredBy || '', tag: field.tag, wire, wireName: 'Custom',
          offset: start, value: `decode-error:${error.message}`, objectPath, kind: 'custom-error',
        });
        sub.errorSuppress = true;
        // consume whatever remains so coverage stays complete
        const rest = sub.end - sub.position;
        if (rest > 0) sub.readBytes(rest, 'unknown-custom');
        return { semantic: null, ast: { kind: 'null', offset: start, endOffset: reader.position } };
      }
      throw error;
    }
    if (sub.remaining() !== 0) {
      if (schema.lenientUnknown) {
        const restHex = sub.readBytes(sub.remaining(), 'unknown-custom').toString('hex');
        schema.unknownFields.push({
          type: field.fieldType, declaringType: field.declaredBy || '', tag: field.tag, wire, wireName: 'Custom',
          offset: start, value: `leftover:${restHex.slice(0, 192)}`, objectPath, kind: 'custom-leftover',
        });
      } else {
        sub.error(`custom serializer ${field.fieldType} left ${sub.remaining()} bytes`);
      }
    }
    return result;
  }
  if (isString(field)) {
    if (wire !== 4) reader.error(`String field ${field.name} uses ${WIRE_NAMES[wire]}`, start);
    return decodePrimitiveRaw(reader, field, field.fieldType);
  }
  if (wire === 0) return decodePrimitiveRaw(reader, field, field.fieldType);
  if (wire === 1) {
    const bytes = reader.readBytes(4, 'fixed32');
    return makeScalar(isFloat(field) ? Number(formatSingle(bytes.readFloatLE(0))) : bytes.readUInt32LE(0),
      isFloat(field) ? 'Single' : typeCode(field), start, reader.position);
  }
  if (wire === 2) {
    const bytes = reader.readBytes(8, 'fixed64');
    return makeScalar(isDouble(field) ? bytes.readDoubleLE(0) : bytes.readBigUInt64LE(0).toString(),
      isDouble(field) ? 'Double' : typeCode(field), start, reader.position);
  }
  if (wire === 3) {
    const length = reader.readLength('object-length');
    const sub = reader.subReader(length, objectPath);
    return decodeObjectPayload(sub, field.fieldType, schema, objectPath, true);
  }
  reader.error(`unsupported wire ${wire} for ${field.name}`, start);
}

function mergeSemantic(defaultValue, decoded) {
  if (!defaultValue || typeof defaultValue !== 'object' || Array.isArray(defaultValue)) return decoded;
  return Object.assign(cloneJson(defaultValue), decoded);
}

function skipUnknownField(blockReader, wire, tag, declaringType, headerOffset, typeName, schema, objectPath) {
  // Lenient mode: the wire format is self-describing for scalar/headered
  // wires, so unknown fields can be skipped while still recording what was
  // seen.  List/Dictionary fields with items cannot be skipped safely because
  // the element wire shape depends on the (unknown) element type.
  const start = headerOffset;
  let value = null;
  let unsupported = false;
  if (wire === 0) {
    value = blockReader.readVarint('unknown-variant').toString();
  } else if (wire === 1) {
    value = blockReader.readBytes(4, 'unknown-fixed32').toString('hex');
  } else if (wire === 2) {
    value = blockReader.readBytes(8, 'unknown-fixed64').toString('hex');
  } else if (wire === 3) {
    const length = blockReader.readLength('unknown-object-length');
    value = `${length}:${blockReader.readBytes(length, 'unknown-object').toString('hex').slice(0, 96)}`;
  } else if (wire === 4) {
    const length = blockReader.readLength('unknown-string-length');
    value = blockReader.readBytes(length, 'unknown-string').toString('utf8').slice(0, 96);
  } else if (wire === 5) {
    const count = Number(blockReader.readVarint('unknown-list-count'));
    if (count === 0) {
      value = 'empty-list';
    } else {
      unsupported = true;
      value = `list-count=${count}`;
    }
  } else if (wire === 6) {
    const count = Number(blockReader.readVarint('unknown-dictionary-count'));
    if (count === 0) {
      value = 'empty-dictionary';
    } else {
      unsupported = true;
      value = `dictionary-count=${count}`;
    }
  } else if (wire === 7) {
    const length = blockReader.readLength('unknown-packed-length');
    value = `${length}:${blockReader.readBytes(length, 'unknown-packed').toString('hex').slice(0, 96)}`;
  } else {
    unsupported = true;
  }
  schema.unknownFields.push({
    type: typeName, declaringType, tag, wire, wireName: WIRE_NAMES[wire],
    offset: start, value, objectPath,
  });
  if (unsupported) {
    blockReader.error(`LENIENT-UNSUPPORTED wire ${wire} for unknown tag ${tag} of ${declaringType} (${value})`, start);
  }
}

function decodeObjectPayload(reader, declaredTypeName, schema, objectPath, allowPrefix) {
  const start = reader.position;
  let actualTypeName = declaredTypeName;
  let prefixTypeId = null;
  if (allowPrefix && reader.remaining() > 0) {
    const saved = reader.position;
    const first = reader.readVarint('object-prefix');
    if (first === 0n && reader.remaining() > 0) {
      // KFB stores the polymorphic type id as a signed Variant.  Positive
      // ids are therefore ZigZag encoded (for example AnimationClipData id 5
      // is written as 0x0a), rather than as the raw unsigned varint used by
      // protobuf-style field headers.
      const encodedTypeId = reader.readVarint('type-id');
      const typeIdBig = zigZag(encodedTypeId);
      if (typeIdBig <= 0n || typeIdBig > 0x7fffffffn) reader.error(`invalid type ID ${typeIdBig}`);
      prefixTypeId = Number(typeIdBig);
      const actual = schema.typesById.get(prefixTypeId);
      if (!actual) reader.error(`unknown type ID ${prefixTypeId}`);
      actualTypeName = actual.fullName;
    } else {
      const decodedFirst = zigZag(first);
      const candidate = decodedFirst > 0n && decodedFirst <= 0x7fffffffn
        ? schema.typesById.get(Number(decodedFirst)) : null;
      const declared = schema.typesByName.get(declaredTypeName);
      if (declared && declared.polymorphic && candidate) {
        prefixTypeId = Number(decodedFirst);
        actualTypeName = candidate.fullName;
      } else {
        reader.position = saved;
        reader.coverage.pop();
      }
    }
  }
  const actualType = schema.typesByName.get(actualTypeName);
  if (!actualType) reader.error(`unknown object type ${actualTypeName}`, start);
  const decoded = {};
  const fields = [];

  // Generated KFB serializers wrap inherited fields in field zero using the
  // Object wire type: 0x03, subitem length, then the base type's field block.
  // This is distinct from the leading zero used by a polymorphic object
  // prefix.  Keeping the base block bounded is also required for duplicate
  // field tags across derived/base classes.
  function decodeFieldBlock(blockReader, declaringType) {
    while (blockReader.remaining() > 0) {
      const headerOffset = blockReader.position;
      const header = blockReader.readVarint('field-header');
      const wire = Number(header & 7n);
      const tagBig = header >> 3n;
      if (wire > 7 || tagBig > 0x7fffffffn) blockReader.error('invalid field header', headerOffset);
      if (tagBig === 0n) {
        if (wire !== 3) blockReader.error(`invalid base-field wire ${wire}`, headerOffset);
        const current = schema.typesByName.get(declaringType);
        if (!current || !current.baseType || !schema.typesByName.has(current.baseType)) {
          blockReader.error(`unexpected base-field block for ${declaringType}`, headerOffset);
        }
        const baseLength = blockReader.readLength('base-object-length');
        const baseReader = blockReader.subReader(baseLength, objectPath);
        decodeFieldBlock(baseReader, current.baseType);
        if (baseReader.remaining() !== 0) baseReader.error(`base object left ${baseReader.remaining()} bytes`);
        continue;
      }
      const tag = Number(tagBig);
      const field = chooseField(schema, actualType, tag, declaringType);
      if (!field) {
        if (schema.lenientUnknown) {
          skipUnknownField(blockReader, wire, tag, declaringType, headerOffset, actualType.fullName, schema, objectPath);
          continue;
        }
        blockReader.error(`unknown tag ${tag} for ${declaringType}`, headerOffset);
      }
      const propertyName = editableFieldName(actualType, field);
      const value = decodeFieldValue(blockReader, wire, field, schema, `${objectPath}.${propertyName}`);
      decoded[propertyName] = value.semantic;
      if (schema.traceFields) {
        schema.traceFields.push({
          phase: 'read', path: objectPath, type: actualType.fullName,
          declaredBy: field.declaredBy, name: field.name, tag,
          value: traceableValue(value.semantic, field, schema),
        });
      }
      fields.push({
        kind: 'field', tag, name: field.name, declaredType: field.fieldType,
        declaredBy: field.declaredBy, wire, wireName: WIRE_NAMES[wire],
        offset: headerOffset, endOffset: blockReader.position, value: value.ast,
      });
    }
  }

  decodeFieldBlock(reader, actualType.fullName);
  const semantic = mergeSemantic(actualType.defaultValue, decoded);
  return {
    semantic,
    ast: {
      kind: 'object', declaredType: declaredTypeName, type: actualTypeName, typeId: prefixTypeId,
      fields, offset: start, endOffset: reader.position,
    },
  };
}

function validateCoverage(coverage, inputLength) {
  const intervals = coverage.filter((entry) => entry.end > entry.start)
    .sort((a, b) => a.start - b.start || a.end - b.end);
  let position = 0;
  for (const interval of intervals) {
    if (interval.start > position) throw new DecodeError(`unconsumed byte range ${position}-${interval.start}`, position);
    if (interval.start < position) {
      // A parent reader reserves a sub-reader range by moving its cursor, but it
      // does not mark that range. Therefore any overlap means a decoder bug.
      throw new DecodeError(`overlapping coverage ${interval.start}-${interval.end}`, interval.start);
    }
    position = interval.end;
  }
  if (position !== inputLength) throw new DecodeError(`unconsumed byte range ${position}-${inputLength}`, position);
  return { coveredBytes: position, intervals: intervals.length, unknownFields: 0 };
}

function decodeKfb(buffer, normalizedSchema, options = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw new Error('KFB input is empty');
  normalizedSchema.lenientUnknown = !!options.lenientUnknown;
  normalizedSchema.unknownFields = [];
  const coverage = [];
  const reader = new Reader(buffer, 0, buffer.length, coverage, '$');
  const result = decodeObjectPayload(reader, normalizedSchema.rootType, normalizedSchema, '$', false);
  if (reader.remaining() !== 0) reader.error(`root object left ${reader.remaining()} bytes`);
  const coverageResult = validateCoverage(coverage, buffer.length);
  coverageResult.unknownFields = normalizedSchema.unknownFields.length;
  return { ...result, coverage: coverageResult, unknownFields: normalizedSchema.unknownFields };
}

function xmlEscape(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function valueToXml(node, indent) {
  const pad = '  '.repeat(indent);
  if (!node || node.kind === 'null') return `${pad}<Null />\n`;
  if (node.kind === 'string') return `${pad}<String>${xmlEscape(node.value)}</String>\n`;
  if (node.kind === 'scalar') return `${pad}<${xmlEscape(node.scalarType || 'Value')}>${xmlEscape(node.value)}</${xmlEscape(node.scalarType || 'Value')}>\n`;
  if (node.kind === 'custom') {
    let out = `${pad}<Custom type="${xmlEscape(node.type)}" value="${xmlEscape(node.value)}">\n`;
    for (const [name, value] of Object.entries(node.components || {})) {
      out += `${pad}  <Component name="${xmlEscape(name)}">${xmlEscape(value)}</Component>\n`;
    }
    return `${out}${pad}</Custom>\n`;
  }
  if (node.kind === 'list' || node.kind === 'array') {
    const tag = node.kind === 'array' ? 'Array' : 'List';
    let out = `${pad}<${tag}${node.packed ? ' packed="true"' : ''}>\n`;
    for (const item of node.items) {
      out += `${pad}  <Item index="${item.index}">\n${valueToXml(item, indent + 2)}${pad}  </Item>\n`;
    }
    return `${out}${pad}</${tag}>\n`;
  }
  if (node.kind === 'dictionary') {
    let out = `${pad}<Dictionary>\n`;
    for (const entry of node.entries) {
      out += `${pad}  <Entry index="${entry.index}">\n${pad}    <Key>\n`;
      out += valueToXml(entry.key, indent + 3);
      out += `${pad}    </Key>\n${pad}    <Value>\n`;
      out += valueToXml(entry.value, indent + 3);
      out += `${pad}    </Value>\n${pad}  </Entry>\n`;
    }
    return `${out}${pad}</Dictionary>\n`;
  }
  if (node.kind === 'object') {
    let out = `${pad}<Object type="${xmlEscape(node.type)}" declaredType="${xmlEscape(node.declaredType)}"`;
    if (node.typeId !== null) out += ` typeId="${node.typeId}"`;
    out += '>\n';
    for (const field of node.fields) {
      out += `${pad}  <Field tag="${field.tag}" name="${xmlEscape(field.name)}" declaredType="${xmlEscape(field.declaredType)}" declaredBy="${xmlEscape(field.declaredBy)}" wire="${field.wireName}">\n`;
      out += valueToXml(field.value, indent + 2);
      out += `${pad}  </Field>\n`;
    }
    return `${out}${pad}</Object>\n`;
  }
  throw new Error(`unsupported XML node kind ${node.kind}`);
}

function toXml(decoded, rootType, inputHash = '') {
  let out = '<?xml version="1.0" encoding="utf-8"?>\n';
  out += `<KFB rootType="${xmlEscape(rootType)}"`;
  if (inputHash) out += ` sha256="${xmlEscape(inputHash)}"`;
  out += '>\n';
  for (const field of decoded.ast.fields) {
    out += `  <Field tag="${field.tag}" name="${xmlEscape(field.name)}" declaredType="${xmlEscape(field.declaredType)}" declaredBy="${xmlEscape(field.declaredBy)}" wire="${field.wireName}">\n`;
    out += valueToXml(field.value, 2);
    out += '  </Field>\n';
  }
  out += '</KFB>\n';
  return out;
}

function encodeVarint(value) {
  let current = BigInt(value);
  const bytes = [];
  do {
    let byte = Number(current & 0x7fn);
    current >>= 7n;
    if (current !== 0n) byte |= 0x80;
    bytes.push(byte);
  } while (current !== 0n);
  return Buffer.from(bytes);
}
function encodeZigZag(value) { const v = BigInt(value); return (v << 1n) ^ (v >> 63n); }
function fieldHeader(tag, wire) { return encodeVarint((BigInt(tag) << 3n) | BigInt(wire)); }
function stringRaw(value) { const data = Buffer.from(value); return Buffer.concat([encodeVarint(data.length), data]); }

class EncodeError extends Error {
  constructor(message, objectPath = '$') {
    super(`${message} (${objectPath})`);
    this.name = 'KfbEncodeError';
    this.objectPath = objectPath;
  }
}

function encodeError(message, objectPath) { throw new EncodeError(message, objectPath); }

function integerValue(value, objectPath) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) encodeError(`integer is outside the exact JSON range: ${value}`, objectPath);
    return BigInt(value);
  }
  if (typeof value === 'string' && /^-?\d+$/.test(value)) return BigInt(value);
  encodeError(`expected an integer, got ${JSON.stringify(value)}`, objectPath);
}

function encodePrimitiveRaw(value, field, declaredType, objectPath) {
  if (isString(field, declaredType)) return stringRaw(String(value));
  if (isFloat(field, declaredType)) {
    const output = Buffer.allocUnsafe(4);
    output.writeFloatLE(Number(value), 0);
    return output;
  }
  if (isDouble(field, declaredType)) {
    const output = Buffer.allocUnsafe(8);
    output.writeDoubleLE(Number(value), 0);
    return output;
  }
  if (isBoolean(field, declaredType)) {
    if (value !== true && value !== false && value !== 0 && value !== 1) {
      encodeError(`expected Boolean, got ${JSON.stringify(value)}`, objectPath);
    }
    return encodeVarint(value === true || value === 1 ? 1n : 0n);
  }
  const integer = integerValue(value, objectPath);
  if (isUnsigned(field, declaredType) && integer < 0n) encodeError(`negative unsigned integer ${integer}`, objectPath);
  return encodeVarint(isSigned(field, declaredType) ? encodeZigZag(integer) : integer);
}

function parseCustomParts(value, count) {
  const text = String(value);
  if (count === 1) return [text];
  const raw = text.split(',');
  if (raw.length < count) raw.push(...Array(count - raw.length).fill(''));
  if (raw.length > count) {
    const fixed = raw.slice(0, count - 1);
    fixed.push(raw.slice(count - 1).join(','));
    return fixed;
  }
  return raw;
}

function encodeAnimationCurve(value, objectPath) {
  const sections = String(value).split('|');
  if (sections.length < 3) encodeError('invalid AnimationCurve JSON value', objectPath);
  const preWrapMode = integerValue(sections[0], `${objectPath}.preWrapMode`);
  const postWrapMode = integerValue(sections[1], `${objectPath}.postWrapMode`);
  const count = Number(integerValue(sections[2], `${objectPath}.count`));
  if (!Number.isInteger(count) || count < 0 || count > 1000000 || sections.length !== count + 3) {
    encodeError(`invalid AnimationCurve key count ${count}`, objectPath);
  }
  const parts = [encodeVarint(encodeZigZag(preWrapMode)), encodeVarint(encodeZigZag(postWrapMode)),
    encodeVarint(encodeZigZag(BigInt(count)))];
  for (let index = 0; index < count; index += 1) {
    const values = sections[index + 3].split(',');
    if (values.length !== 7) encodeError(`AnimationCurve key ${index} must contain seven values`, objectPath);
    for (let component = 0; component < 6; component += 1) {
      const output = Buffer.allocUnsafe(4);
      output.writeFloatLE(Number(values[component]), 0);
      parts.push(output);
    }
    parts.push(encodeVarint(encodeZigZag(integerValue(values[6], `${objectPath}.keys[${index}].weightedMode`))));
  }
  return Buffer.concat(parts);
}

function encodeCustom(value, typeName, objectPath) {
  if (typeName === 'UnityEngine.AnimationCurve') return encodeAnimationCurve(value, objectPath);
  const layout = customLayout(typeName);
  if (!layout) encodeError(`unknown custom serializer ${typeName}`, objectPath);
  const parts = parseCustomParts(value, layout.components.length);
  const encoded = [];
  for (let index = 0; index < layout.components.length; index += 1) {
    const component = layout.components[index];
    const name = typeof component === 'string' ? component : component.name;
    const encoding = typeof component === 'string' ? layout.encoding : component.encoding;
    const componentPath = `${objectPath}.${name}`;
    const current = parts[index];
    if (encoding === 'sint64' || encoding === 'sint32') {
      encoded.push(encodeVarint(encodeZigZag(integerValue(current, componentPath))));
    } else if (encoding === 'uint64' || encoding === 'uint32') {
      const integer = integerValue(current, componentPath);
      if (integer < 0n) encodeError(`negative unsigned integer ${integer}`, componentPath);
      encoded.push(encodeVarint(integer));
    } else if (encoding === 'string') encoded.push(stringRaw(current));
    else if (encoding === 'float32') {
      const output = Buffer.allocUnsafe(4); output.writeFloatLE(Number(current), 0); encoded.push(output);
    } else if (encoding === 'float64') {
      const output = Buffer.allocUnsafe(8); output.writeDoubleLE(Number(current), 0); encoded.push(output);
    } else if (encoding === 'byte') {
      const integer = integerValue(current, componentPath);
      if (integer < 0n || integer > 255n) encodeError(`byte is outside 0..255: ${integer}`, componentPath);
      encoded.push(Buffer.from([Number(integer)]));
    } else encodeError(`unsupported custom component encoding ${encoding}`, componentPath);
  }
  return Buffer.concat(encoded);
}

function actualTypeForValue(value, declaredType, schema, objectPath) {
  let actual = schema.typesByName.get(declaredType);
  if (value && typeof value === 'object' && value.$tid !== undefined) {
    const typeId = Number(value.$tid);
    if (!Number.isInteger(typeId) || !schema.typesById.has(typeId)) encodeError(`unknown $tid ${value.$tid}`, objectPath);
    actual = schema.typesById.get(typeId);
  }
  if (!actual) encodeError(`unknown object type ${declaredType}`, objectPath);
  let current = actual;
  let assignable = actual.fullName === declaredType;
  const visited = new Set();
  while (!assignable && current && current.baseType && !visited.has(current.fullName)) {
    visited.add(current.fullName);
    assignable = current.baseType === declaredType;
    current = schema.typesByName.get(current.baseType);
  }
  if (!assignable && schema.typesByName.has(declaredType)) {
    encodeError(`type ${actual.fullName} is not assignable to ${declaredType}`, objectPath);
  }
  return actual;
}

function isPrimitiveDeclared(field, declaredType) {
  return isString(field, declaredType) || isBoolean(field, declaredType) || isSigned(field, declaredType) ||
    isUnsigned(field, declaredType) || isFloat(field, declaredType) || isDouble(field, declaredType) || field.is_enum;
}

function encodeDeclaredItem(value, field, declaredType, schema, objectPath) {
  const custom = schema.customTypes.has(declaredType) || field.has_custom_serializer;
  const nestedList = isListType(declaredType);
  const object = schema.typesByName.has(declaredType) || field.is_kfb_serializable || field.polymorphic;
  if (value === null || value === undefined) {
    if (custom || nestedList || object) return Buffer.from([0]);
    encodeError(`null primitive collection item ${declaredType}`, objectPath);
  }
  if (custom) {
    const body = encodeCustom(value, declaredType, objectPath);
    return Buffer.concat([Buffer.from([3]), encodeVarint(body.length), body]);
  }
  if (isPrimitiveDeclared(field, declaredType)) return encodePrimitiveRaw(value, field, declaredType, objectPath);
  if (nestedList) {
    const elementType = firstGenericTypeArgument(declaredType);
    if (!elementType) encodeError(`cannot determine nested List element type ${declaredType}`, objectPath);
    const body = encodeCollection(value, {
      name: 'Item', fieldType: declaredType, is_list: true, is_array: false, is_dictionary: false,
      element_type: elementType,
    }, schema, objectPath);
    return Buffer.concat([Buffer.from([5]), body]);
  }
  if (object) {
    const body = encodeObjectPayload(value, declaredType, schema, objectPath, true);
    return Buffer.concat([Buffer.from([3]), encodeVarint(body.length), body]);
  }
  encodeError(`unsupported declared collection item type ${declaredType}`, objectPath);
}

function encodeCollection(value, field, schema, objectPath) {
  if (field.is_dictionary) {
    // A Map preserves insertion order (JS objects reorder integer-like keys),
    // which allows wire-order-faithful re-encoding; plain objects keep
    // numeric-ascending order for JSON-driven workflows.
    const isMap = typeof Map !== 'undefined' && value instanceof Map;
    if (!isMap && (!value || typeof value !== 'object' || Array.isArray(value))) {
      encodeError('Dictionary value must be an object', objectPath);
    }
    const entries = isMap ? [...value.entries()] : Object.entries(value);
    const parts = [encodeVarint(entries.length)];
    for (let index = 0; index < entries.length; index += 1) {
      const [keyValue, itemValue] = entries[index];
      const keyField = { fieldType: field.key_type, type_code: '', is_enum: false };
      parts.push(encodeDeclaredItem(keyValue, keyField, field.key_type, schema, `${objectPath}[${index}].Key`));
      const valueField = { ...field, fieldType: field.value_type, is_dictionary: false, is_list: false,
        is_array: false, has_custom_serializer: schema.customTypes.has(field.value_type),
        is_kfb_serializable: schema.typesByName.has(field.value_type) };
      parts.push(encodeDeclaredItem(itemValue, valueField, field.value_type, schema, `${objectPath}[${index}].Value`));
    }
    return Buffer.concat(parts);
  }
  if (!Array.isArray(value)) encodeError('List/Array value must be an array', objectPath);
  const elementType = field.element_type;
  if (!elementType) encodeError(`collection field ${field.name} lacks element_type`, objectPath);
  const parts = [encodeVarint(value.length)];
  for (let index = 0; index < value.length; index += 1) {
    const elementField = { ...field, fieldType: elementType, is_dictionary: false, is_list: false,
      is_array: false, has_custom_serializer: schema.customTypes.has(elementType),
      is_kfb_serializable: schema.typesByName.has(elementType) };
    parts.push(encodeDeclaredItem(value[index], elementField, elementType, schema, `${objectPath}[${index}]`));
  }
  return Buffer.concat(parts);
}

function wireForField(field, schema) {
  if (field.is_dictionary) return 6;
  if (field.is_list || field.is_array) return 5;
  if (schema.customTypes.has(field.fieldType) || field.has_custom_serializer) return 3;
  if (isString(field)) return 4;
  if (field.wire_type_hint === 'Fixed32' || isFloat(field)) return 1;
  if (field.wire_type_hint === 'Fixed64' || isDouble(field)) return 2;
  if (schema.typesByName.has(field.fieldType) || field.is_kfb_serializable || field.polymorphic) return 3;
  return 0;
}

function encodeFieldValue(value, wire, field, schema, objectPath) {
  if (wire === 6 || wire === 5) return encodeCollection(value, field, schema, objectPath);
  if (wire === 7) {
    if (!Array.isArray(value) || !field.element_type) encodeError('Packed value must be a typed array', objectPath);
    const elementField = { ...field, fieldType: field.element_type, is_array: false, is_list: false, is_dictionary: false };
    const body = Buffer.concat(value.map((item, index) =>
      encodePrimitiveRaw(item, elementField, field.element_type, `${objectPath}[${index}]`)));
    return Buffer.concat([encodeVarint(body.length), body]);
  }
  if (schema.customTypes.has(field.fieldType) || field.has_custom_serializer) {
    const body = encodeCustom(value, field.fieldType, objectPath);
    return Buffer.concat([encodeVarint(body.length), body]);
  }
  if (wire === 3) {
    const body = encodeObjectPayload(value, field.fieldType, schema, objectPath, true);
    return Buffer.concat([encodeVarint(body.length), body]);
  }
  return encodePrimitiveRaw(value, field, field.fieldType, objectPath);
}

function scalarStringFormIsZero(form) {
  // Custom-serializer values are carried in semantic JSON as their scalar
  // string form (e.g. "0" for FScalar, "0,0,0" for FVector3/Vector3).
  if (typeof form === 'number') return form === 0;
  if (typeof form !== 'string') return false;
  const parts = form.split(',');
  if (parts.length === 0) return false;
  return parts.every((p) => /^\s*-?\d+(\.\d+)?\s*$/.test(p) && Number(p) === 0);
}

function traceableValue(semantic, field, schema) {
  // Trace payloads keep leaf values only; nested lists/dictionaries/objects
  // would duplicate the whole decoded tree per trace entry.
  if (field.is_list || field.is_dictionary || field.is_array) return null;
  if (schema.customTypes.has(field.fieldType) || field.has_custom_serializer) return semantic;
  if (schema.typesByName.has(field.fieldType) || field.is_kfb_serializable || field.polymorphic) return null;
  return semantic === undefined ? null : semantic;
}

function encodeObjectPayload(value, declaredTypeName, schema, objectPath, includePrefix) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) encodeError('object value must be a JSON object', objectPath);
  const actualType = actualTypeForValue(value, declaredTypeName, schema, objectPath);
  const chunks = [];
  if (includePrefix) {
    if (actualType.typeId === null) encodeError(`object type ${actualType.fullName} has no type ID`, objectPath);
    chunks.push(Buffer.from([0]), encodeVarint(encodeZigZag(BigInt(actualType.typeId))));
  }

  // KFBWriter.SkipDefault: the runtime serializer omits any field whose value
  // equals the field's recorded default (KFBWriter.WriteField(tag, value,
  // defaultValue) returns early when SkipDefault is set and value equals
  // defaultValue).  The per-field defaults are the C# field initializers,
  // mirrored per type in the schema's default_json (flattened across the base
  // chain exactly like the generated WriteField methods).  A field without a
  // recorded default is always written.
  function customScalarEquals(valueForm, defaultForm) {
    if (valueForm === defaultForm) return true;
    if (typeof valueForm !== 'string' || typeof defaultForm !== 'string') return false;
    const left = valueForm.split(',');
    const right = defaultForm.split(',');
    if (left.length !== right.length) return false;
    return left.every((part, index) => {
      const a = part.trim();
      const b = right[index].trim();
      if (a === b) return true;
      if (/^-?\d+$/.test(a) && /^-?\d+$/.test(b)) return BigInt(a) === BigInt(b);
      const na = Number(a);
      const nb = Number(b);
      return Number.isFinite(na) && Number.isFinite(nb) && na === nb;
    });
  }

  function isOmittableDefault(fieldValue, field) {
    // Wire-verified flag: this (instance type, field) combination is always
    // present in runtime-written KFB, even when the value equals the default
    // (e.g. KH.KHScriptData.argStr "" / KH.KHFrameData empty lists).  Omitting
    // it would deviate from the game writer's byte layout.
    if (field.always_write) return false;
    // Duplicate field names across the base chain (e.g. ignoreInvincible on
    // both KH.AOEScriptArg and KH.AreaTestScriptArg) are stored under prefixed
    // keys ("AOEScriptArg.ignoreInvincible") in default_json and semantic JSON;
    // resolve the default with the same editable-name rule used for values.
    const defKey = editableFieldName(actualType, field);
    const def = actualType.defaultValue
      ? (actualType.defaultValue[defKey] !== undefined ? actualType.defaultValue[defKey]
        : actualType.defaultValue[field.name])
      : undefined;
    if (def === undefined || def === null) return false;
    if (field.is_list || field.is_array) {
      return Array.isArray(fieldValue) && fieldValue.length === 0 &&
        Array.isArray(def) && def.length === 0;
    }
    if (field.is_dictionary) {
      if (!fieldValue || typeof fieldValue !== 'object' || Array.isArray(fieldValue)) return false;
      const emptyValue = fieldValue instanceof Map ? fieldValue.size === 0 : Object.keys(fieldValue).length === 0;
      return emptyValue && typeof def === 'object' && def !== null && !Array.isArray(def) &&
        Object.keys(def).length === 0;
    }
    if (field.has_custom_serializer || schema.customTypes.has(field.fieldType)) {
      return customScalarEquals(fieldValue, def);
    }
    if (schema.typesByName.has(field.fieldType) || field.is_kfb_serializable || field.polymorphic) {
      return false;
    }
    if (isString(field)) return fieldValue === def;
    if (isBoolean(field)) return fieldValue === !!def;
    // Numeric and enum fields: compare exact integer forms first (Int64
    // values travel as decimal strings), then fall back to float equality.
    const a = String(fieldValue);
    const b = String(def);
    if (a === b) return true;
    if (/^-?\d+$/.test(a) && /^-?\d+$/.test(b)) return BigInt(a) === BigInt(b);
    const na = Number(a);
    const nb = Number(b);
    return Number.isFinite(na) && Number.isFinite(nb) && na === nb;
  }

  function encodeFieldBlock(declaringType) {
    const parts = [];
    const fields = actualType.fields.filter((field) => field.declaredBy === declaringType);
    for (const field of fields) {
      const propertyName = editableFieldName(actualType, field);
      let selectedName = propertyName;
      if (!Object.prototype.hasOwnProperty.call(value, selectedName)) {
        const duplicates = actualType.fields.filter((candidate) => candidate.name === field.name);
        const last = duplicates[duplicates.length - 1];
        if (last !== field || !Object.prototype.hasOwnProperty.call(value, field.name)) continue;
        selectedName = field.name;
      }
      const fieldValue = value[selectedName];
      if (fieldValue === null || fieldValue === undefined) {
        if (schema.traceFields) {
          schema.traceFields.push({ phase: 'skip-null', path: objectPath, type: actualType.fullName,
            declaredBy: declaringType, name: field.name, tag: field.tag, value: null });
        }
        continue;
      }
      if (isOmittableDefault(fieldValue, field)) {
        if (schema.traceFields) {
          schema.traceFields.push({ phase: 'omit', path: objectPath, type: actualType.fullName,
            declaredBy: declaringType, name: field.name, tag: field.tag,
            value: traceableValue(fieldValue, field, schema) });
        }
        continue;
      }
      const wire = wireForField(field, schema);
      parts.push(fieldHeader(field.tag, wire));
      parts.push(encodeFieldValue(fieldValue, wire, field, schema, `${objectPath}.${selectedName}`));
      if (schema.traceFields) {
        schema.traceFields.push({ phase: 'write', path: objectPath, type: actualType.fullName,
          declaredBy: declaringType, name: field.name, tag: field.tag,
          value: traceableValue(fieldValue, field, schema) });
      }
    }
    const declaring = schema.typesByName.get(declaringType);
    if (declaring && declaring.baseType && schema.typesByName.has(declaring.baseType)) {
      // The runtime serializer always emits the base-field block when the base
      // type is a schema type, even when the block is empty (no own fields and
      // no deeper base). Verified against runtime-exported KFB bytes for
      // KFL.KFLBoolConstantInfo (base chain KFLConstantInfo -> KFLValueInfo).
      // The base block comes BEFORE the declaring type's own fields: wire
      // verified on KH.PlaySoundArg (prefix, then `03 06` base block with
      // KHScriptData fields, then soundID/uniqueName) and KFL.KFLBoolParameterInfo.
      const base = encodeFieldBlock(declaring.baseType);
      parts.unshift(fieldHeader(0, 3), encodeVarint(base.length), base);
    }
    return Buffer.concat(parts);
  }

  chunks.push(encodeFieldBlock(actualType.fullName));
  return Buffer.concat(chunks);
}

function encodeKfb(semantic, normalizedSchema) {
  if (!semantic || typeof semantic !== 'object' || Array.isArray(semantic)) throw new Error('KFB semantic root must be an object');
  const output = encodeObjectPayload(semantic, normalizedSchema.rootType, normalizedSchema, '$', false);
  if (output.length === 0) throw new Error('encoded KFB is empty');
  return output;
}

function runSyntheticSelfTest() {
  const childBody = Buffer.concat([Buffer.from([0]), encodeVarint(encodeZigZag(2)),
    fieldHeader(1, 0), encodeVarint(encodeZigZag(-7))]);
  const scalarBody = encodeVarint(encodeZigZag(6442450944n)); // 1.5 in signed 32.32 fixed point
  const packedBody = Buffer.concat([encodeVarint(encodeZigZag(-1)), encodeVarint(encodeZigZag(2))]);
  const wide = 9007199254740993n;
  const fixture = Buffer.concat([
    fieldHeader(1, 4), stringRaw('Actor'),
    fieldHeader(2, 0), encodeVarint(encodeZigZag(-42)),
    fieldHeader(3, 5), encodeVarint(2), stringRaw('a'), stringRaw('b'),
    fieldHeader(4, 6), encodeVarint(1), encodeVarint(encodeZigZag(5)), stringRaw('five'),
    fieldHeader(5, 3), encodeVarint(childBody.length), childBody,
    fieldHeader(6, 3), encodeVarint(scalarBody.length), scalarBody,
    fieldHeader(7, 0), encodeVarint(encodeZigZag(wide)),
    fieldHeader(8, 7), encodeVarint(packedBody.length), packedBody,
    fieldHeader(9, 5), encodeVarint(1), Buffer.from([0]),
  ]);
  const schema = normalizeSchema({
    schema_version: 1, root_type: 'Test.Root', polymorphic_type_field: '$type',
    custom_serializers: [{ type: 'Morefun.LockStep.FScalar', serializer_type: 'Synthetic' }],
    types: [
      { type_id: 1, full_name: 'Test.Root', fields: [
        { tag: 1, name: 'name', field_type: 'System.String', type_code: 'String' },
        { tag: 2, name: 'signed', field_type: 'System.Int32', type_code: 'Int32' },
        { tag: 3, name: 'names', field_type: 'System.Collections.Generic.List<System.String>', is_list: true, element_type: 'System.String' },
        { tag: 4, name: 'map', field_type: 'System.Collections.Generic.Dictionary<System.Int32,System.String>', is_dictionary: true, key_type: 'System.Int32', value_type: 'System.String' },
        { tag: 5, name: 'child', field_type: 'Test.Child', is_kfb_serializable: true },
        { tag: 6, name: 'scalar', field_type: 'Morefun.LockStep.FScalar', has_custom_serializer: true },
        { tag: 7, name: 'wide', field_type: 'System.Int64', type_code: 'Int64' },
        { tag: 8, name: 'packed', field_type: 'System.Int32[]', is_array: true, element_type: 'System.Int32' },
        { tag: 9, name: 'nullableChildren', field_type: 'System.Collections.Generic.List<Test.Child>', is_list: true, element_type: 'Test.Child' },
      ] },
      { type_id: 2, full_name: 'Test.Child', fields: [
        { tag: 1, name: 'value', field_type: 'System.Int32', type_code: 'Int32' },
      ] },
    ],
  });
  const decoded = decodeKfb(fixture, schema);
  const expected = {
    name: 'Actor', signed: -42, names: ['a', 'b'], map: { 5: 'five' }, child: { value: -7 },
    scalar: '6442450944', wide: wide.toString(), packed: [-1, 2], nullableChildren: [null],
  };
  if (JSON.stringify(decoded.semantic) !== JSON.stringify(expected)) throw new Error('synthetic semantic mismatch');
  const xml = toXml(decoded, schema.rootType);
  if (!xml.includes('name="signed"') || !xml.includes('<Dictionary>') || !xml.includes('type="Test.Child"')) {
    throw new Error('synthetic XML mismatch');
  }
  const reencoded = encodeKfb(decoded.semantic, schema);
  const decodedAgain = decodeKfb(reencoded, schema);
  if (JSON.stringify(decodedAgain.semantic) !== JSON.stringify(expected)) throw new Error('synthetic encode round-trip mismatch');
  return {
    fixtureBytes: fixture.length,
    reencodedBytes: reencoded.length,
    encodeRoundTrip: true,
    semantic: decoded.semantic,
    coverage: decoded.coverage,
    reencodedCoverage: decodedAgain.coverage,
    xmlBytes: Buffer.byteLength(xml),
  };
}

module.exports = {
  DecodeError,
  EncodeError,
  normalizeSchema,
  loadSchema,
  decodeKfb,
  encodeKfb,
  toXml,
  runSyntheticSelfTest,
};
