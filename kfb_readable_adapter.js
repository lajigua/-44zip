'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const FORMAT_NAME = 'KH.ActorData runtime-readable v2';
const LEGACY_FORMAT_NAME = 'KH.ActorData runtime-readable v1';
const ROOT_ALIASES = {
  shadowName: 'shadow',
  viewHeight: 'vHeight',
  viewWidth: 'vWth',
  viewZSzie: 'vZSz',
  unitMaterial: 'uMat',
  sufferAudioID: 'sAID',
  deadAudioID: 'dAID',
  needGroupChange: 'nGrpChg',
  defSelfGroupID: 'dSelfGrpID',
  CreateScriptID: 'CrScptID',
  defaultVKey: 'dVK',
  disappearVKey: 'disappVK',
  reviveFlag: 'rFlg',
};
const ROOT_VECTOR_PREFIXES = { mapOffset: 'mOft', shadowSize: 'shdS' };
const BOX_VECTOR_PREFIXES = {
  attack_pos: 'apos', attack_size: 'asize', weapon_pos: 'wpos', weapon_size: 'wsize',
  hurt_pos0: 'hpos0', hurt_size0: 'hsize0', hurt_pos1: 'hpos1', hurt_size1: 'hsize1',
  hurt_pos2: 'hpos2', hurt_size2: 'hsize2',
};
const SCRIPT_RUNTIME_FIELDS = {
  key: { type: 'System.String', offset: '0x20', value: '' },
  motionFrameIndex: { type: 'System.Int32', offset: '0x28', value: 0 },
  scriptIndex: { type: 'System.Int32', offset: '0x2C', value: 0 },
};
const CUSTOM_LAYOUTS = {
  'Morefun.LockStep.FScalar': ['value'],
  'KH.FVector2': ['x', 'y'],
  'KH.FVector3': ['x', 'y', 'z'],
  'KH.FVector4': ['x', 'y', 'z', 'w'],
  'KH.FQuaternion': ['x', 'y', 'z', 'w'],
  'KH.FColor': ['r', 'g', 'b', 'a'],
  'KH.TSKFLFloatArg': ['source', 'variable', 'value'],
  'KH.TSKFLIntArg': ['source', 'variable', 'value'],
  'KH.TSKFLStringArg': ['source', 'variable', 'value'],
  'UnityEngine.Vector2': ['x', 'y'],
  'UnityEngine.Vector3': ['x', 'y', 'z'],
  'UnityEngine.Vector4': ['x', 'y', 'z', 'w'],
  'UnityEngine.Vector3Int': ['x', 'y', 'z'],
  'UnityEngine.Quaternion': ['x', 'y', 'z', 'w'],
  'UnityEngine.Rect': ['x', 'y', 'width', 'height'],
  'UnityEngine.Bounds': ['cx', 'cy', 'cz', 'ex', 'ey', 'ez'],
  'UnityEngine.Color': ['r', 'g', 'b', 'a'],
  'UnityEngine.Color32': ['r', 'g', 'b', 'a'],
};

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function fail(message, objectPath = '') {
  throw new Error(`${message}${objectPath ? ` (${objectPath})` : ''}`);
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function normalizeHexOffset(value) {
  const match = /^0x([0-9a-f]+)$/i.exec(String(value || ''));
  return match ? `0x${match[1].toUpperCase()}` : String(value || '');
}

function stripAssemblyType(typeName) {
  const text = String(typeName || '').trim();
  if (!text.includes('`')) return text.split(',')[0].trim();
  return text;
}

function firstGenericTypeArgument(typeName) {
  const text = String(typeName || '');
  const start = text.indexOf('[[');
  if (start < 0) return null;
  let depth = 0;
  for (let index = start + 2; index < text.length; index += 1) {
    const char = text[index];
    if (char === '[') depth += 1;
    else if (char === ']') {
      if (depth === 0) return text.slice(start + 2, index).trim();
      depth -= 1;
    } else if (char === ',' && depth === 0) return text.slice(start + 2, index).trim();
  }
  return null;
}

function isListDeclared(typeName) {
  return String(typeName || '').startsWith('System.Collections.Generic.List`1[[');
}

function directTypeName(typeName, inGeneric = false) {
  const text = stripAssemblyType(typeName);
  const primitives = {
    'System.Boolean': 'Boolean', 'System.Byte': 'Byte', 'System.SByte': 'SByte',
    'System.Int16': 'Int16', 'System.UInt16': 'UInt16', 'System.Int32': 'Int32',
    'System.UInt32': 'UInt32', 'System.Int64': 'Int64', 'System.UInt64': 'UInt64',
    'System.Single': 'Single', 'System.Double': 'Double', 'System.Decimal': 'Decimal',
    'System.Char': 'Char', 'System.String': 'String', 'System.Object': 'Object',
  };
  if (primitives[text]) return inGeneric ? text : primitives[text];
  if (text === 'Morefun.LockStep.FScalar') return 'FScalar';
  if (!inGeneric && /^(?:KH|UnityEngine)\./.test(text)) return text.slice(text.lastIndexOf('.') + 1);
  return text;
}

function displayType(field, layoutField = null) {
  if (field.display_type || field.displayType) return field.display_type || field.displayType;
  if (field.is_dictionary) {
    return `Dictionary<${directTypeName(field.key_type, true)},${directTypeName(field.value_type, true)}>`;
  }
  if (field.is_list) return `List<${directTypeName(field.element_type, true)}>`;
  if (field.is_array) return `${directTypeName(field.element_type, true)}[]`;
  return directTypeName(layoutField?.type || field.fieldType);
}

function displayTypeMatches(field, actual, expected) {
  if (actual === expected) return true;
  // Runtime exports from older builds shortened nested enum names (for example
  // `Quality` or `iTween.EaseType`). Keep those v2 documents writable after a
  // newer schema records the declaring type with the IL2CPP `+` separator.
  if (!field.is_enum && !expected.includes('+') && !expected.includes('.')) return false;
  const aliases = new Set([expected]);
  const add = (value) => {
    if (!value) return;
    const text = String(value);
    aliases.add(text);
    aliases.add(text.replace(/\./g, '+'));
    aliases.add(text.replace(/\+/g, '.'));
    aliases.add(text.split(/[+.]/).pop());
    const shortOwner = text.replace(/[+.][^.]+$/, '').split('.').pop();
    const leaf = text.split(/[+.]/).pop();
    if (shortOwner && leaf) {
      aliases.add(`${shortOwner}+${leaf}`);
      aliases.add(`${shortOwner}.${leaf}`);
    }
  };
  add(field.field_type || field.fieldType);
  add(expected);
  return aliases.has(actual);
}

function isPrimitiveType(field, typeName = field.fieldType) {
  const code = field.type_code || field.typeCode || '';
  return field.is_enum || /^System\.(?:Boolean|Byte|SByte|Int16|UInt16|Int32|UInt32|Int64|UInt64|Single|Double|Decimal|Char|String)$/.test(typeName) ||
    /^(?:Boolean|Byte|SByte|Int16|UInt16|Int32|UInt32|Int64|UInt64|Single|Double|Decimal|Char|String)$/.test(code);
}

function typeForSemantic(value, declaredType, schema, objectPath) {
  let type = schema.typesByName.get(declaredType);
  if (value && typeof value === 'object' && !Array.isArray(value) && value.$tid !== undefined) {
    type = schema.typesById.get(Number(value.$tid));
    if (!type) fail(`unknown KFB type ID ${value.$tid}`, objectPath);
  }
  if (!type) fail(`unknown object type ${declaredType}`, objectPath);
  return type;
}

function isDerivedFrom(type, baseName, schema) {
  let current = type;
  const seen = new Set();
  while (current && !seen.has(current.fullName)) {
    if (current.fullName === baseName) return true;
    seen.add(current.fullName);
    current = current.baseType ? schema.typesByName.get(current.baseType) : null;
  }
  return false;
}

function schemaField(type, name) {
  const dot = String(name).lastIndexOf('.');
  const rawName = dot >= 0 ? String(name).slice(dot + 1) : String(name);
  const qualifier = dot >= 0 ? String(name).slice(0, dot) : null;
  const candidates = type.fields.filter((field) => field.name === rawName);
  if (qualifier) {
    const qualified = candidates.find((field) => field.declaredBy === qualifier || field.declaredBy.endsWith(`.${qualifier}`));
    if (qualified) return qualified;
  }
  return candidates[candidates.length - 1] || null;
}

function layoutFieldFor(type, field, layout, schema) {
  const direct = layout.types?.[field.declaredBy]?.fields?.[field.name];
  if (direct) return direct;
  let current = type;
  const seen = new Set();
  while (current && !seen.has(current.fullName)) {
    seen.add(current.fullName);
    const found = layout.types?.[current.fullName]?.fields?.[field.name] ||
      layout.types?.[current.fullName]?.fields?.[`<${field.name}>k__BackingField`];
    if (found) return found;
    current = current.baseType ? schema.typesByName.get(current.baseType) : null;
  }
  return null;
}

function offsetFor(type, field, layout, schema) {
  return normalizeHexOffset(layoutFieldFor(type, field, layout, schema)?.offset || `tag:${field.tag}`);
}

function numberOrString(text) {
  if (typeof text !== 'string' || !/^-?\d+$/.test(text)) return text;
  const integer = BigInt(text);
  return integer >= BigInt(Number.MIN_SAFE_INTEGER) && integer <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(integer) : text;
}

function scalarRuntime(value) {
  return {
    'Int64 rawValue': numberOrString(String(value)),
    'Boolean HasInit': true,
  };
}

function scalarFromRuntime(value, objectPath) {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'bigint') return String(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('FScalar must be an object', objectPath);
  const key = Object.keys(value).find((name) => {
    const parsed = parseReadableFieldKey(name);
    return parsed?.name === 'rawValue' || name === 'rawValue';
  });
  if (!key) fail('FScalar lacks rawValue', objectPath);
  const raw = value[key];
  if ((typeof raw !== 'number' && typeof raw !== 'string') || !/^-?\d+$/.test(String(raw))) {
    fail(`invalid FScalar rawValue ${raw}`, objectPath);
  }
  return String(raw);
}

function expandCustom(value, typeName) {
  if (value === null || value === undefined) return value;
  if (typeName === 'Morefun.LockStep.FScalar') return scalarRuntime(value);
  const components = CUSTOM_LAYOUTS[typeName];
  if (!components || typeName === 'UnityEngine.AnimationCurve') return value;
  const parts = String(value).split(',');
  const result = {};
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index];
    const componentValue = parts[index] === undefined ? '' : parts[index];
    if (/^(?:KH\.F|Morefun\.LockStep\.F)/.test(typeName)) {
      result[`FScalar ${component}`] = scalarRuntime(componentValue);
    } else {
      let componentType = 'Single';
      let runtimeName = component;
      if (typeName === 'UnityEngine.Vector3Int') componentType = 'Int32';
      else if (typeName === 'UnityEngine.Color32') componentType = 'Byte';
      else if (/^KH\.TSKFL/.test(typeName)) {
        runtimeName = { source: 'isKFL', variable: 'kflName', value: 'rawValue' }[component];
        componentType = component === 'source' ? 'Boolean' :
          (component === 'variable' || (component === 'value' && typeName === 'KH.TSKFLStringArg') ? 'String' :
            (component === 'value' && typeName === 'KH.TSKFLFloatArg' ? 'FScalar' : 'Int32'));
      }
      result[`${componentType} ${runtimeName}`] = componentType === 'FScalar'
        ? scalarRuntime(componentValue)
        : (componentType === 'Boolean' ? componentValue !== '0' : numberOrString(componentValue));
    }
  }
  return result;
}

function collapseCustom(value, typeName, objectPath) {
  if (value === null || value === undefined || typeof value === 'string' || typeof value === 'number') return String(value);
  if (typeName === 'Morefun.LockStep.FScalar') return scalarFromRuntime(value, objectPath);
  const components = CUSTOM_LAYOUTS[typeName];
  if (!components || typeName === 'UnityEngine.AnimationCurve') {
    fail(`custom type ${typeName} must use its canonical string form`, objectPath);
  }
  const parts = [];
  for (const component of components) {
    const runtimeName = /^KH\.TSKFL/.test(typeName)
      ? { source: 'isKFL', variable: 'kflName', value: 'rawValue' }[component] : component;
    const key = Object.keys(value).find((name) => {
      const parsed = parseReadableFieldKey(name);
      return parsed?.name === runtimeName || name === runtimeName;
    });
    if (!key) fail(`custom type ${typeName} lacks component ${component}`, objectPath);
    const isFixedScalar = /^(?:KH\.F|Morefun\.LockStep\.F)/.test(typeName) ||
      (typeName === 'KH.TSKFLFloatArg' && component === 'value');
    if (typeName.startsWith('KH.TSKFL') && component === 'source') parts.push(value[key] ? '1' : '0');
    else parts.push(isFixedScalar ? scalarFromRuntime(value[key], `${objectPath}.${component}`) : String(value[key]));
  }
  return parts.join(',');
}

function wrapCollectionObject(fields, type) {
  return { [type.fullName]: fields };
}

function semanticValueToRuntime(value, field, schema, layout, objectPath, collectionItem = false) {
  if (value === null || value === undefined) return null;
  if (field.has_custom_serializer || schema.customTypes.has(field.fieldType)) return expandCustom(value, field.fieldType);
  if (field.is_list || field.is_array) {
    if (!Array.isArray(value)) fail(`${field.name} must be an array`, objectPath);
    return value.map((item, index) => collectionItemToRuntime(item, field.element_type, schema, layout,
      `${objectPath}[${index}]`));
  }
  if (field.is_dictionary) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${field.name} must be a dictionary`, objectPath);
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = collectionItemToRuntime(item, field.value_type, schema, layout, `${objectPath}[${JSON.stringify(key)}]`);
    }
    return result;
  }
  if (isPrimitiveType(field)) return value;
  const type = typeForSemantic(value, field.fieldType, schema, objectPath);
  const fields = semanticObjectToFields(value, type.fullName, schema, layout, objectPath);
  return collectionItem || type.fullName !== field.fieldType ? wrapCollectionObject(fields, type) : fields;
}

function collectionItemToRuntime(value, declaredType, schema, layout, objectPath) {
  if (value === null || value === undefined) return null;
  if (schema.customTypes.has(declaredType)) return expandCustom(value, declaredType);
  if (isListDeclared(declaredType)) {
    if (!Array.isArray(value)) fail(`nested ${declaredType} must be an array`, objectPath);
    const elementType = firstGenericTypeArgument(declaredType);
    if (!elementType) fail(`cannot resolve nested List element type ${declaredType}`, objectPath);
    return value.map((item, index) => collectionItemToRuntime(item, elementType, schema, layout, `${objectPath}[${index}]`));
  }
  const pseudo = { fieldType: declaredType, type_code: '', is_enum: false };
  if (isPrimitiveType(pseudo, declaredType)) return value;
  const type = typeForSemantic(value, declaredType, schema, objectPath);
  return wrapCollectionObject(semanticObjectToFields(value, type.fullName, schema, layout, objectPath), type);
}

function semanticObjectToFields(value, declaredType, schema, layout, objectPath = '$') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('object value must be an object', objectPath);
  const type = typeForSemantic(value, declaredType, schema, objectPath);
  const result = {};
  for (const [name, item] of Object.entries(value)) {
    if (name === '$tid') continue;
    const field = schemaField(type, name);
    if (!field) fail(`schema type ${type.fullName} has no field ${name}`, objectPath);
    const layoutField = layoutFieldFor(type, field, layout, schema);
    const key = `${displayType(field, layoutField)} ${name}`;
    result[key] = semanticValueToRuntime(item, field, schema, layout, `${objectPath}.${name}`);
  }
  return result;
}

function semanticToRuntimeJson(semantic, schema, layout) {
  const type = typeForSemantic(semantic, schema.rootType, schema, '$');
  return {
    format: FORMAT_NAME,
    class: type.fullName,
    actorData: semanticObjectToFields(semantic, schema.rootType, schema, layout),
  };
}

function parseReadableFieldKey(key) {
  const text = String(key);
  const legacy = /^(.*?)\s+([^\s@]+)\s+@(0x[0-9a-f]+|tag:\d+|component:\d+)$/i.exec(text);
  if (legacy) return { type: legacy[1].trim(), name: legacy[2], location: legacy[3], version: 1 };
  const current = /^(.*?)\s+([^\s@]+)$/.exec(text);
  return current ? { type: current[1].trim(), name: current[2], location: null, version: 2 } : null;
}

function unwrapRuntimeObject(value, declaredType, schema, objectPath) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('object value must be an object', objectPath);
  const keys = Object.keys(value);
  if (keys.length === 1 && schema.typesByName.has(keys[0])) return { typeName: keys[0], fields: value[keys[0]] };
  return { typeName: declaredType, fields: value };
}

function parsePrimitive(value, field, objectPath) {
  const typeName = field.fieldType;
  if (typeName === 'System.String' || (field.type_code || '') === 'String') {
    if (typeof value !== 'string') fail(`field ${field.name} must be a string`, objectPath);
    return value;
  }
  if (typeName === 'System.Boolean' || (field.type_code || '') === 'Boolean') {
    if (typeof value === 'boolean') return value;
    if (/^(?:true|1)$/i.test(String(value))) return true;
    if (/^(?:false|0)$/i.test(String(value))) return false;
    fail(`field ${field.name} must be Boolean`, objectPath);
  }
  if (/Int64|UInt64/.test(typeName) || /Int64|UInt64/.test(field.type_code || '')) {
    if (!/^-?\d+$/.test(String(value))) fail(`field ${field.name} must be a 64-bit integer`, objectPath);
    return String(value);
  }
  if (/Single|Double|Decimal/.test(typeName) || /Single|Double|Decimal/.test(field.type_code || '')) {
    const number = Number(value);
    if (!Number.isFinite(number)) fail(`field ${field.name} must be finite`, objectPath);
    return number;
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number)) fail(`field ${field.name} must be a safe integer`, objectPath);
  return number;
}

function runtimeCollectionItemToSemantic(value, declaredType, schema, layout, objectPath) {
  if (value === null || value === undefined) return null;
  if (schema.customTypes.has(declaredType)) return collapseCustom(value, declaredType, objectPath);
  if (isListDeclared(declaredType)) {
    if (!Array.isArray(value)) fail(`nested ${declaredType} must be an array`, objectPath);
    const elementType = firstGenericTypeArgument(declaredType);
    if (!elementType) fail(`cannot resolve nested List element type ${declaredType}`, objectPath);
    return value.map((item, index) => runtimeCollectionItemToSemantic(item, elementType, schema, layout, `${objectPath}[${index}]`));
  }
  const pseudo = { name: 'Item', fieldType: declaredType, type_code: '', is_enum: false };
  if (isPrimitiveType(pseudo, declaredType)) return parsePrimitive(value, pseudo, objectPath);
  const unwrapped = unwrapRuntimeObject(value, declaredType, schema, objectPath);
  return runtimeFieldsToSemantic(unwrapped.fields, unwrapped.typeName, schema, layout, objectPath);
}

function runtimeValueToSemantic(value, field, schema, layout, objectPath) {
  if (value === null || value === undefined) return null;
  if (field.has_custom_serializer || schema.customTypes.has(field.fieldType)) {
    return collapseCustom(value, field.fieldType, objectPath);
  }
  if (field.is_list || field.is_array) {
    if (!Array.isArray(value)) fail(`${field.name} must be an array`, objectPath);
    return value.map((item, index) => runtimeCollectionItemToSemantic(item, field.element_type, schema, layout,
      `${objectPath}[${index}]`));
  }
  if (field.is_dictionary) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${field.name} must be a dictionary`, objectPath);
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = runtimeCollectionItemToSemantic(item, field.value_type, schema, layout,
        `${objectPath}[${JSON.stringify(key)}]`);
    }
    return result;
  }
  if (isPrimitiveType(field)) return parsePrimitive(value, field, objectPath);
  const unwrapped = unwrapRuntimeObject(value, field.fieldType, schema, objectPath);
  return runtimeFieldsToSemantic(unwrapped.fields, unwrapped.typeName, schema, layout, objectPath);
}

function runtimeFieldsToSemantic(fields, typeName, schema, layout, objectPath = '$') {
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) fail('runtime object fields must be an object', objectPath);
  const type = schema.typesByName.get(typeName);
  if (!type) fail(`unknown runtime class ${typeName}`, objectPath);
  const result = clone(type.defaultValue || {});
  if (type.typeId !== null) result.$tid = type.typeId;
  for (const [key, value] of Object.entries(fields)) {
    const parsed = parseReadableFieldKey(key);
    if (!parsed) fail(`invalid readable field key ${key}`, objectPath);
    const field = schemaField(type, parsed.name);
    if (!field) {
      const runtimeField = SCRIPT_RUNTIME_FIELDS[parsed.name];
      if (runtimeField && isDerivedFrom(type, 'KH.KHScriptData', schema)) {
        if (JSON.stringify(value) !== JSON.stringify(runtimeField.value)) {
          fail(`runtime-only field ${parsed.name} is not serialized and must keep default ${JSON.stringify(runtimeField.value)}`, objectPath);
        }
        continue;
      }
      fail(`unknown field ${parsed.name} for ${type.fullName}`, objectPath);
    }
    const expectedType = displayType(field, layoutFieldFor(type, field, layout, schema));
    if (!displayTypeMatches(field, parsed.type, expectedType)) {
      fail(`field ${parsed.name} type is ${parsed.type}; expected ${expectedType}`, objectPath);
    }
    result[parsed.name] = runtimeValueToSemantic(value, field, schema, layout, `${objectPath}.${parsed.name}`);
  }
  return result;
}

function runtimeJsonToSemantic(document, schema, layout) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) fail('runtime JSON root must be an object');
  const typeName = document.class || schema.rootType;
  if (!document.actorData || typeof document.actorData !== 'object') fail('runtime JSON lacks actorData');
  return runtimeFieldsToSemantic(document.actorData, typeName, schema, layout);
}

function xmlEscape(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function xmlUnescape(value) {
  return String(value).replace(/&(?:#x([0-9a-f]+)|#(\d+)|quot|apos|lt|gt|amp);/gi, (match, hex, decimal) => {
    if (hex) return String.fromCodePoint(parseInt(hex, 16));
    if (decimal) return String.fromCodePoint(parseInt(decimal, 10));
    return { '&quot;': '"', '&apos;': "'", '&lt;': '<', '&gt;': '>', '&amp;': '&' }[match.toLowerCase()] || match;
  });
}

class XmlNode {
  constructor(name, attributes = {}) { this.name = name; this.attributes = attributes; this.children = []; this.text = ''; }
  child(name) { return this.children.find((item) => item.name === name) || null; }
  childrenNamed(name) { return this.children.filter((item) => item.name === name); }
}

function parseXml(text) {
  const input = String(text).replace(/^\uFEFF/, '');
  const stack = [];
  let root = null;
  let position = 0;
  while (position < input.length) {
    const open = input.indexOf('<', position);
    if (open < 0) break;
    if (open > position && stack.length) stack[stack.length - 1].text += xmlUnescape(input.slice(position, open));
    if (input.startsWith('<!--', open)) {
      const end = input.indexOf('-->', open + 4); if (end < 0) fail('unterminated XML comment'); position = end + 3; continue;
    }
    if (input.startsWith('<?', open)) {
      const end = input.indexOf('?>', open + 2); if (end < 0) fail('unterminated XML declaration'); position = end + 2; continue;
    }
    const end = input.indexOf('>', open + 1); if (end < 0) fail('unterminated XML tag');
    let token = input.slice(open + 1, end).trim();
    if (token.startsWith('!')) fail('XML declarations other than the XML header are unsupported');
    if (token.startsWith('/')) {
      const name = token.slice(1).trim();
      const node = stack.pop();
      if (!node || node.name !== name) fail(`XML close tag ${name} does not match ${node?.name || 'none'}`);
    } else {
      const selfClosing = token.endsWith('/');
      if (selfClosing) token = token.slice(0, -1).trim();
      const nameMatch = /^([^\s/>]+)/.exec(token); if (!nameMatch) fail('invalid XML start tag');
      const name = nameMatch[1];
      const attributes = {};
      const rest = token.slice(name.length);
      const attrRegex = /([^\s=]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
      let match;
      let consumed = '';
      while ((match = attrRegex.exec(rest)) !== null) {
        attributes[match[1]] = xmlUnescape(match[2] === undefined ? match[3] : match[2]);
        consumed += match[0];
      }
      const residue = rest.replace(attrRegex, '').trim();
      if (residue) fail(`invalid XML attributes in <${name}>: ${residue}`);
      const node = new XmlNode(name, attributes);
      if (stack.length) stack[stack.length - 1].children.push(node);
      else if (root) fail('XML contains multiple roots');
      else root = node;
      if (!selfClosing) stack.push(node);
    }
    position = end + 1;
  }
  if (stack.length) fail(`unclosed XML tag ${stack[stack.length - 1].name}`);
  if (!root) fail('XML document is empty');
  return root;
}

class XmlWriter {
  constructor() { this.lines = ['<?xml version="1.0" encoding="utf-8"?>']; }
  attrs(attributes) {
    return Object.entries(attributes).filter(([, value]) => value !== undefined && value !== null)
      .map(([name, value]) => ` ${name}="${xmlEscape(value)}"`).join('');
  }
  open(indent, name, attributes = {}) { this.lines.push(`${'  '.repeat(indent)}<${name}${this.attrs(attributes)}>`); }
  close(indent, name) { this.lines.push(`${'  '.repeat(indent)}</${name}>`); }
  empty(indent, name, attributes = {}) { this.lines.push(`${'  '.repeat(indent)}<${name}${this.attrs(attributes)} />`); }
  text(indent, name, value, attributes = {}) {
    this.lines.push(`${'  '.repeat(indent)}<${name}${this.attrs(attributes)}>${xmlEscape(value)}</${name}>`);
  }
  finish() { return `${this.lines.join('\n')}\n`; }
}

function xmlScalar(value) {
  if (typeof value === 'boolean') return value ? 'True' : 'False';
  return String(value);
}

function parseXmlPrimitive(value, field, objectPath) {
  return parsePrimitive(value, field, objectPath);
}

function emitXmlDeclaredItem(writer, indent, tag, attributes, item, declaredType, schema, objectPath) {
  if (item === null) { writer.empty(indent, tag, { ...attributes, null: 'true' }); return; }
  if (schema.customTypes.has(declaredType) || isPrimitiveType({ fieldType: declaredType, type_code: '', is_enum: false }, declaredType)) {
    writer.empty(indent, tag, { ...attributes, value: xmlScalar(item) });
    return;
  }
  if (isListDeclared(declaredType)) {
    if (!Array.isArray(item)) fail(`nested ${declaredType} must be an array`, objectPath);
    const elementType = firstGenericTypeArgument(declaredType);
    if (!elementType) fail(`cannot resolve nested List element type ${declaredType}`, objectPath);
    writer.open(indent, tag, attributes);
    writer.open(indent + 1, 'List', { elementType });
    for (let index = 0; index < item.length; index += 1) {
      emitXmlDeclaredItem(writer, indent + 2, 'Item', { index }, item[index], elementType, schema, `${objectPath}[${index}]`);
    }
    writer.close(indent + 1, 'List');
    writer.close(indent, tag);
    return;
  }
  const type = typeForSemantic(item, declaredType, schema, objectPath);
  writer.open(indent, tag, { ...attributes, kfbType: type.fullName });
  emitGenericFields(writer, indent + 1, item, type, schema, objectPath);
  writer.close(indent, tag);
}

function emitGenericCollection(writer, indent, field, value, schema, objectPath) {
  const attributes = { kind: field.is_dictionary ? 'dictionary' : 'list' };
  if (field.element_type) attributes.elementType = field.element_type;
  if (field.key_type) attributes.keyType = field.key_type;
  if (field.value_type) attributes.valueType = field.value_type;
  writer.open(indent, field.name, attributes);
  if (field.is_dictionary) {
    for (const [key, item] of Object.entries(value || {})) {
      emitXmlDeclaredItem(writer, indent + 1, 'Entry', { key }, item, field.value_type, schema, `${objectPath}[${key}]`);
    }
  } else {
    for (let index = 0; index < (value || []).length; index += 1) {
      emitXmlDeclaredItem(writer, indent + 1, 'Item', { index }, value[index], field.element_type, schema, `${objectPath}[${index}]`);
    }
  }
  writer.close(indent, field.name);
}

function emitGenericFields(writer, indent, semantic, type, schema, objectPath, excluded = new Set()) {
  const nested = [];
  const attributes = {};
  for (const [name, value] of Object.entries(semantic)) {
    if (name === '$tid' || excluded.has(name)) continue;
    const field = schemaField(type, name);
    if (!field) fail(`schema type ${type.fullName} has no field ${name}`, objectPath);
    if (value === null) nested.push({ field, value, name });
    else if (field.is_list || field.is_array || field.is_dictionary || (!isPrimitiveType(field) && !field.has_custom_serializer && !schema.customTypes.has(field.fieldType))) {
      nested.push({ field, value, name });
    } else attributes[name] = xmlScalar(value);
  }
  if (Object.keys(attributes).length) writer.empty(indent, 'Fields', attributes);
  for (const { field, value, name } of nested) {
    const xmlField = name === field.name ? field : { ...field, name };
    if (value === null) writer.empty(indent, name, { null: 'true' });
    else if (field.is_list || field.is_array || field.is_dictionary) emitGenericCollection(writer, indent, xmlField, value, schema, `${objectPath}.${name}`);
    else {
      const childType = typeForSemantic(value, field.fieldType, schema, `${objectPath}.${name}`);
      writer.open(indent, name, { kfbType: childType.fullName });
      emitGenericFields(writer, indent + 1, value, childType, schema, `${objectPath}.${name}`);
      writer.close(indent, name);
    }
  }
}

function emitScript(writer, indent, script, schema, objectPath) {
  const type = typeForSemantic(script, 'KH.KHScriptData', schema, objectPath);
  const attributes = { kfbType: type.fullName };
  const nested = [];
  for (const [name, value] of Object.entries(script)) {
    if (name === '$tid') continue;
    const field = schemaField(type, name);
    if (!field) fail(`schema type ${type.fullName} has no field ${name}`, objectPath);
    if (value !== null && !field.is_list && !field.is_array && !field.is_dictionary &&
        (isPrimitiveType(field) || field.has_custom_serializer || schema.customTypes.has(field.fieldType))) {
      attributes[name] = xmlScalar(value);
    } else nested.push({ field, value, name });
  }
  if (!nested.length) writer.empty(indent, 'KHScriptData', attributes);
  else {
    writer.open(indent, 'KHScriptData', attributes);
    for (const { field, value, name } of nested) {
      const xmlField = name === field.name ? field : { ...field, name };
      if (value === null) writer.empty(indent + 1, name, { null: 'true' });
      else if (field.is_list || field.is_array || field.is_dictionary) emitGenericCollection(writer, indent + 1, xmlField, value, schema, `${objectPath}.${name}`);
      else {
        const childType = typeForSemantic(value, field.fieldType, schema, `${objectPath}.${name}`);
        writer.open(indent + 1, name, { kfbType: childType.fullName });
        emitGenericFields(writer, indent + 2, value, childType, schema, `${objectPath}.${name}`);
        writer.close(indent + 1, name);
      }
    }
    writer.close(indent, 'KHScriptData');
  }
}

function emitFrame(writer, indent, frame, schema, objectPath, dictionaryKey = null) {
  const type = typeForSemantic(frame, 'KH.KHFrameData', schema, objectPath);
  const attributes = { kfbType: type.fullName, index: frame.index, once: frame.once ? 1 : 0 };
  if (dictionaryKey !== null) attributes.dictKey = dictionaryKey;
  writer.open(indent, 'KHFrameData', attributes);
  const known = new Set(['index', 'once', 'scriptDatas', 'scriptDatasForSounds', 'scriptDatasForEffects']);
  for (let index = 0; index < (frame.scriptDatas || []).length; index += 1) {
    emitScript(writer, indent + 1, frame.scriptDatas[index], schema, `${objectPath}.scriptDatas[${index}]`);
  }
  for (const group of ['scriptDatasForSounds', 'scriptDatasForEffects']) {
    const scripts = frame[group] || [];
    if (!scripts.length) continue;
    const tag = group === 'scriptDatasForSounds' ? 'ScriptDatasForSounds' : 'ScriptDatasForEffects';
    writer.open(indent + 1, tag);
    for (let index = 0; index < scripts.length; index += 1) emitScript(writer, indent + 2, scripts[index], schema, `${objectPath}.${group}[${index}]`);
    writer.close(indent + 1, tag);
  }
  emitGenericFields(writer, indent + 1, frame, type, schema, objectPath, known);
  writer.close(indent, 'KHFrameData');
}

function vectorParts(value, count) {
  const parts = String(value || '').split(',');
  while (parts.length < count) parts.push('0');
  return parts.slice(0, count);
}

function emitBox(writer, indent, box, schema, objectPath) {
  const type = typeForSemantic(box, 'KH.AnimationBoxData', schema, objectPath);
  const attributes = { kfbType: type.fullName };
  const nested = [];
  for (const [name, value] of Object.entries(box)) {
    if (name === '$tid') continue;
    const field = schemaField(type, name);
    if (!field) fail(`schema type ${type.fullName} has no field ${name}`, objectPath);
    const prefix = BOX_VECTOR_PREFIXES[name];
    if (prefix && schema.customTypes.has(field.fieldType)) {
      const parts = vectorParts(value, CUSTOM_LAYOUTS[field.fieldType]?.length || 3);
      const names = CUSTOM_LAYOUTS[field.fieldType] || parts.map((_, index) => String(index));
      for (let index = 0; index < names.length; index += 1) attributes[`${prefix}_${names[index]}`] = parts[index];
    } else if (isPrimitiveType(field) || field.has_custom_serializer || schema.customTypes.has(field.fieldType)) {
      attributes[name] = xmlScalar(value);
    } else nested.push({ field, value, name });
  }
  if (!nested.length) writer.empty(indent, 'KHAttackData', attributes);
  else {
    writer.open(indent, 'KHAttackData', attributes);
    for (const { field, value, name } of nested) {
      const xmlField = name === field.name ? field : { ...field, name };
      if (field.is_list || field.is_array || field.is_dictionary) emitGenericCollection(writer, indent + 1, xmlField, value, schema, `${objectPath}.${name}`);
      else if (value === null) writer.empty(indent + 1, name, { null: 'true' });
      else {
        const childType = typeForSemantic(value, field.fieldType, schema, `${objectPath}.${name}`);
        writer.open(indent + 1, name, { kfbType: childType.fullName });
        emitGenericFields(writer, indent + 2, value, childType, schema, `${objectPath}.${name}`);
        writer.close(indent + 1, name);
      }
    }
    writer.close(indent, 'KHAttackData');
  }
}

function emitAnimationFrame(writer, indent, frame, schema, objectPath, dictionaryKey) {
  const type = typeForSemantic(frame, 'KH.AnimationFrame', schema, objectPath);
  const attributes = { kfbType: type.fullName, index: frame.index, etype: frame.eventType, dictKey: dictionaryKey };
  writer.open(indent, 'KHKeyFrameData', attributes);
  if (frame.boxData) emitBox(writer, indent + 1, frame.boxData, schema, `${objectPath}.boxData`);
  if (frame.frameData) emitFrame(writer, indent + 1, frame.frameData, schema, `${objectPath}.frameData`);
  emitGenericFields(writer, indent + 1, frame, type, schema, objectPath,
    new Set(['index', 'eventType', 'boxData', 'frameData']));
  writer.close(indent, 'KHKeyFrameData');
}

function emitClip(writer, indent, clip, schema, objectPath, listIndex) {
  const type = typeForSemantic(clip, 'KH.AnimationClipData', schema, objectPath);
  const attributes = {
    kfbType: type.fullName, listIndex, name: clip.name, tf: clip.totalframes, rf: clip.renderframes,
    loop: clip.loop ? 'True' : 'False', snames: `${(clip.statenames || []).join(';')}${(clip.statenames || []).length ? ';' : ''}`,
  };
  writer.open(indent, 'AniClipData', attributes);
  for (const [key, value] of Object.entries(clip.keyframes || {})) {
    emitAnimationFrame(writer, indent + 1, value, schema, `${objectPath}.keyframes[${JSON.stringify(key)}]`, key);
  }
  const known = new Set(['name', 'statenames', 'totalframes', 'renderframes', 'loop', 'keyframes']);
  emitGenericFields(writer, indent + 1, clip, type, schema, objectPath, known);
  writer.close(indent, 'AniClipData');
}

function semanticToLegacyXml(semantic, schema, inputHash = '') {
  const type = typeForSemantic(semantic, schema.rootType, schema, '$');
  const writer = new XmlWriter();
  const attributes = { kfbType: type.fullName, format: 'KFB-readable-v1' };
  if (inputHash) attributes.kfbSha256 = inputHash;
  const nested = [];
  for (const [name, value] of Object.entries(semantic)) {
    if (name === '$tid' || name === 'objectFrames' || name === 'clipsDataList') continue;
    const field = schemaField(type, name);
    if (!field) fail(`schema type ${type.fullName} has no field ${name}`, '$');
    const prefix = ROOT_VECTOR_PREFIXES[name];
    if (prefix && schema.customTypes.has(field.fieldType)) {
      const components = CUSTOM_LAYOUTS[field.fieldType] || [];
      const parts = vectorParts(value, components.length);
      for (let index = 0; index < components.length; index += 1) attributes[`${prefix}_${components[index]}`] = parts[index];
    } else if (value !== null && !field.is_list && !field.is_array && !field.is_dictionary &&
        (isPrimitiveType(field) || field.has_custom_serializer || schema.customTypes.has(field.fieldType))) {
      attributes[ROOT_ALIASES[name] || name] = xmlScalar(value);
    } else nested.push({ field, value, name });
  }
  writer.open(0, 'AnimationData', attributes);
  if (semantic.objectFrames && typeof semantic.objectFrames === 'object') {
    writer.open(1, 'ObjectFrames');
    for (const [key, frame] of Object.entries(semantic.objectFrames)) emitFrame(writer, 2, frame, schema, `$.objectFrames[${key}]`, key);
    writer.close(1, 'ObjectFrames');
  }
  for (const { field, value, name } of nested) {
    const xmlField = name === field.name ? field : { ...field, name };
    if (value === null) writer.empty(1, name, { null: 'true' });
    else if (field.is_list || field.is_array || field.is_dictionary) emitGenericCollection(writer, 1, xmlField, value, schema, `$.${name}`);
    else {
      const childType = typeForSemantic(value, field.fieldType, schema, `$.${name}`);
      writer.open(1, name, { kfbType: childType.fullName });
      emitGenericFields(writer, 2, value, childType, schema, `$.${name}`);
      writer.close(1, name);
    }
  }
  for (let index = 0; index < (semantic.clipsDataList || []).length; index += 1) {
    emitClip(writer, 1, semantic.clipsDataList[index], schema, `$.clipsDataList[${index}]`, index);
  }
  writer.close(0, 'AnimationData');
  return writer.finish();
}

function parseXmlDeclaredItem(node, declaredType, schema, objectPath) {
  if (node.attributes.null === 'true') return null;
  if (schema.customTypes.has(declaredType)) return node.attributes.value;
  const pseudo = { name: 'Item', fieldType: declaredType, type_code: '', is_enum: false };
  if (isPrimitiveType(pseudo, declaredType)) return parseXmlPrimitive(node.attributes.value, pseudo, objectPath);
  if (isListDeclared(declaredType)) {
    const list = node.child('List');
    if (!list) fail(`nested ${declaredType} XML item lacks List`, objectPath);
    const elementType = firstGenericTypeArgument(declaredType);
    if (!elementType) fail(`cannot resolve nested List element type ${declaredType}`, objectPath);
    return list.childrenNamed('Item').map((item, index) => parseXmlDeclaredItem(item, elementType, schema, `${objectPath}[${index}]`));
  }
  return parseGenericObject(node, declaredType, schema, objectPath);
}

function parseGenericCollection(node, field, schema, objectPath) {
  if (field.is_dictionary) {
    const result = {};
    for (const entry of node.childrenNamed('Entry')) {
      const key = entry.attributes.key;
      if (key === undefined) fail(`dictionary Entry lacks key`, objectPath);
      result[key] = parseXmlDeclaredItem(entry, field.value_type, schema, `${objectPath}[${key}]`);
    }
    return result;
  }
  return node.childrenNamed('Item').map((item, index) => parseXmlDeclaredItem(item, field.element_type, schema, `${objectPath}[${index}]`));
}

function templateScalarNodeValue(node, field, objectPath) {
  if (node.name === 'Null') return null;
  const text = node.attributes.value !== undefined ? node.attributes.value : node.text;
  if (field.has_custom_serializer) return String(text);
  return parseXmlPrimitive(text, field, objectPath);
}

function parseTemplateDeclaredValue(node, declaredType, field, schema, objectPath) {
  if (!node) fail('template Field has no value node', objectPath);
  if (node.name === 'Null') return null;
  if (node.name === 'KFBObject') return parseTemplateObject(node, declaredType, schema, objectPath);
  if (node.name === 'List' || node.name === 'Array') {
    const elementType = field.element_type || node.attributes.elementType;
    if (!elementType) fail('template List lacks elementType', objectPath);
    return node.childrenNamed('Item').map((item, index) => {
      const valueNode = item.children[0] || item;
      const itemField = { name: 'Item', fieldType: elementType, type_code: '',
        has_custom_serializer: schema.customTypes.has(elementType), is_list: false, is_array: false, is_dictionary: false };
      return parseTemplateDeclaredValue(valueNode, elementType, itemField, schema, `${objectPath}[${index}]`);
    });
  }
  if (node.name === 'Dictionary') {
    const keyType = field.key_type || node.attributes.keyType;
    const valueType = field.value_type || node.attributes.valueType;
    if (!keyType || !valueType) fail('template Dictionary lacks keyType/valueType', objectPath);
    const result = {};
    for (const [index, entry] of node.childrenNamed('Entry').entries()) {
      const keyContainer = entry.child('Key');
      const valueContainer = entry.child('Value');
      if (!keyContainer || !valueContainer) fail('template Dictionary Entry lacks Key/Value', `${objectPath}[${index}]`);
      const keyField = { name: 'Key', fieldType: keyType, type_code: '', has_custom_serializer: schema.customTypes.has(keyType) };
      const valueField = { name: 'Value', fieldType: valueType, type_code: '', has_custom_serializer: schema.customTypes.has(valueType) };
      const key = parseTemplateDeclaredValue(keyContainer.children[0] || keyContainer, keyType, keyField, schema, `${objectPath}[${index}].Key`);
      result[String(key)] = parseTemplateDeclaredValue(valueContainer.children[0] || valueContainer, valueType, valueField, schema, `${objectPath}[${index}].Value`);
    }
    return result;
  }
  if (schema.customTypes.has(declaredType) || field.has_custom_serializer) {
    return node.attributes.value !== undefined ? String(node.attributes.value) : String(node.text);
  }
  if (isPrimitiveType(field, declaredType)) return templateScalarNodeValue(node, field, objectPath);
  if (node.name === 'String' && !schema.typesByName.has(declaredType)) {
    try { return JSON.parse(node.text); } catch { return node.text; }
  }
  fail(`unsupported template value <${node.name}> for ${declaredType}`, objectPath);
}

function parseTemplateObject(node, declaredType, schema, objectPath) {
  const typeName = node.attributes.kfbType || declaredType;
  const type = schema.typesByName.get(typeName);
  if (!type) fail(`unknown template kfbType ${typeName}`, objectPath);
  const result = clone(type.defaultValue || {});
  if (type.typeId !== null) result.$tid = type.typeId;
  for (const fieldNode of node.childrenNamed('Field')) {
    const name = fieldNode.attributes.name;
    if (!name) fail('template Field lacks name', objectPath);
    const field = schemaField(type, name);
    if (!field) fail(`unknown template field ${name} for ${type.fullName}`, objectPath);
    result[name] = parseTemplateDeclaredValue(fieldNode.children[0], field.fieldType, field, schema, `${objectPath}.${name}`);
  }
  return result;
}

function parseGenericObject(node, declaredType, schema, objectPath, attributeAliases = {}) {
  const typeName = node.attributes.kfbType || declaredType;
  const type = schema.typesByName.get(typeName);
  if (!type) fail(`unknown XML kfbType ${typeName}`, objectPath);
  const result = clone(type.defaultValue || {});
  if (type.typeId !== null) result.$tid = type.typeId;
  const fieldsNodes = node.childrenNamed('Fields');
  const attributes = { ...node.attributes };
  for (const fieldsNode of fieldsNodes) Object.assign(attributes, fieldsNode.attributes);
  const inverseAliases = Object.fromEntries(Object.entries(attributeAliases).map(([field, alias]) => [alias, field]));
  for (const [attributeName, value] of Object.entries(attributes)) {
    if (['kfbType', 'format', 'kfbSha256', 'listIndex', 'dictKey', 'key', 'index', 'null', 'kind', 'elementType', 'keyType', 'valueType'].includes(attributeName)) continue;
    const fieldName = inverseAliases[attributeName] || attributeName;
    const field = schemaField(type, fieldName);
    if (!field) continue;
    if (field.has_custom_serializer || schema.customTypes.has(field.fieldType)) result[fieldName] = value;
    else if (isPrimitiveType(field)) result[fieldName] = parseXmlPrimitive(value, field, `${objectPath}.${fieldName}`);
  }
  for (const child of node.children) {
    if (child.name === 'Fields') continue;
    if (child.name === 'Field') {
      const fieldName = child.attributes.name;
      if (!fieldName) fail('template Field lacks name', objectPath);
      const field = schemaField(type, fieldName);
      if (!field) fail(`unknown template field ${fieldName} for ${type.fullName}`, objectPath);
      result[fieldName] = parseTemplateDeclaredValue(child.children[0], field.fieldType, field, schema, `${objectPath}.${fieldName}`);
      continue;
    }
    const field = schemaField(type, child.name);
    if (!field) continue;
    if (child.attributes.null === 'true') result[child.name] = null;
    else if (field.is_list || field.is_array || field.is_dictionary) result[child.name] = parseGenericCollection(child, field, schema, `${objectPath}.${child.name}`);
    else result[child.name] = parseGenericObject(child, field.fieldType, schema, `${objectPath}.${child.name}`);
  }
  return result;
}

function parseScript(node, schema, objectPath) {
  if (!node.attributes.kfbType && node.attributes.scriptType !== undefined) {
    const scriptType = Number(node.attributes.scriptType);
    const candidates = [...schema.typesByName.values()].filter((type) =>
      type.defaultValue?.scriptType === scriptType && isDerivedFrom(type, 'KH.KHScriptData', schema));
    if (candidates.length === 1) node.attributes.kfbType = candidates[0].fullName;
  }
  return parseGenericObject(node, 'KH.KHScriptData', schema, objectPath);
}

function parseFrame(node, schema, objectPath) {
  const typeName = node.attributes.kfbType || 'KH.KHFrameData';
  const type = schema.typesByName.get(typeName);
  if (!type) fail(`unknown frame type ${typeName}`, objectPath);
  const result = parseGenericObject(node, typeName, schema, objectPath);
  const indexField = schemaField(type, 'index');
  const onceField = schemaField(type, 'once');
  if (node.attributes.index !== undefined && indexField) result.index = parseXmlPrimitive(node.attributes.index, indexField, `${objectPath}.index`);
  if (node.attributes.once !== undefined && onceField) result.once = parseXmlPrimitive(node.attributes.once, onceField, `${objectPath}.once`);
  result.scriptDatas = node.childrenNamed('KHScriptData').map((child, index) => parseScript(child, schema, `${objectPath}.scriptDatas[${index}]`));
  const sounds = node.child('ScriptDatasForSounds');
  const effects = node.child('ScriptDatasForEffects');
  result.scriptDatasForSounds = sounds ? sounds.childrenNamed('KHScriptData').map((child, index) => parseScript(child, schema, `${objectPath}.scriptDatasForSounds[${index}]`)) : [];
  result.scriptDatasForEffects = effects ? effects.childrenNamed('KHScriptData').map((child, index) => parseScript(child, schema, `${objectPath}.scriptDatasForEffects[${index}]`)) : [];
  return result;
}

function parseBox(node, schema, objectPath) {
  const result = parseGenericObject(node, 'KH.AnimationBoxData', schema, objectPath);
  const type = typeForSemantic(result, 'KH.AnimationBoxData', schema, objectPath);
  for (const [fieldName, prefix] of Object.entries(BOX_VECTOR_PREFIXES)) {
    const field = schemaField(type, fieldName);
    if (!field || !schema.customTypes.has(field.fieldType)) continue;
    const components = CUSTOM_LAYOUTS[field.fieldType] || [];
    if (components.some((name) => node.attributes[`${prefix}_${name}`] !== undefined)) {
      result[fieldName] = components.map((name) => node.attributes[`${prefix}_${name}`] || '0').join(',');
    }
  }
  return result;
}

function parseAnimationFrame(node, schema, objectPath) {
  const typeName = node.attributes.kfbType || 'KH.AnimationFrame';
  const type = schema.typesByName.get(typeName);
  if (!type) fail(`unknown key frame type ${typeName}`, objectPath);
  const result = parseGenericObject(node, typeName, schema, objectPath);
  if (node.attributes.index !== undefined) result.index = parseXmlPrimitive(node.attributes.index, schemaField(type, 'index'), `${objectPath}.index`);
  if (node.attributes.etype !== undefined) result.eventType = parseXmlPrimitive(node.attributes.etype, schemaField(type, 'eventType'), `${objectPath}.eventType`);
  const box = node.child('KHAttackData'); if (box) result.boxData = parseBox(box, schema, `${objectPath}.boxData`);
  const frame = node.child('KHFrameData'); if (frame) result.frameData = parseFrame(frame, schema, `${objectPath}.frameData`);
  return result;
}

function parseClip(node, schema, objectPath) {
  const typeName = node.attributes.kfbType || 'KH.AnimationClipData';
  const type = schema.typesByName.get(typeName);
  if (!type) fail(`unknown clip type ${typeName}`, objectPath);
  const result = parseGenericObject(node, typeName, schema, objectPath);
  const attrFields = { name: 'name', tf: 'totalframes', rf: 'renderframes', loop: 'loop' };
  for (const [attribute, fieldName] of Object.entries(attrFields)) {
    if (node.attributes[attribute] !== undefined) result[fieldName] = parseXmlPrimitive(node.attributes[attribute], schemaField(type, fieldName), `${objectPath}.${fieldName}`);
  }
  result.statenames = String(node.attributes.snames || '').split(';').filter((value) => value !== '');
  result.keyframes = {};
  for (const child of node.childrenNamed('KHKeyFrameData')) {
    const key = child.attributes.dictKey ?? child.attributes.index;
    if (key === undefined) fail('KHKeyFrameData lacks dictKey/index', objectPath);
    result.keyframes[key] = parseAnimationFrame(child, schema, `${objectPath}.keyframes[${key}]`);
  }
  return result;
}

function legacyXmlToSemantic(text, schema) {
  const root = parseXml(text);
  if (root.name === 'KFBObject') return parseTemplateObject(root, root.attributes.kfbType || schema.rootType, schema, '$');
  if (root.name === 'KHScriptData') return parseScript(root, schema, '$');
  if (root.name !== 'AnimationData') fail(`XML root must be AnimationData, got ${root.name}`);
  const typeName = root.attributes.kfbType || schema.rootType;
  const type = schema.typesByName.get(typeName);
  if (!type) fail(`unknown root kfbType ${typeName}`);
  const result = parseGenericObject(root, typeName, schema, '$', ROOT_ALIASES);
  for (const [fieldName, prefix] of Object.entries(ROOT_VECTOR_PREFIXES)) {
    const field = schemaField(type, fieldName);
    const components = CUSTOM_LAYOUTS[field?.fieldType] || [];
    if (field && components.some((name) => root.attributes[`${prefix}_${name}`] !== undefined)) {
      result[fieldName] = components.map((name) => root.attributes[`${prefix}_${name}`] || '0').join(',');
    }
  }
  const objectFrames = root.child('ObjectFrames');
  result.objectFrames = {};
  if (objectFrames) {
    for (const frameNode of objectFrames.childrenNamed('KHFrameData')) {
      const key = frameNode.attributes.dictKey ?? frameNode.attributes.index;
      if (key === undefined) fail('ObjectFrames KHFrameData lacks dictKey/index');
      result.objectFrames[key] = parseFrame(frameNode, schema, `$.objectFrames[${key}]`);
    }
  }
  result.clipsDataList = root.childrenNamed('AniClipData').map((node, index) => parseClip(node, schema, `$.clipsDataList[${index}]`));
  return result;
}

function buildDumpLayout(dumpPath, schema) {
  const absolute = path.resolve(dumpPath);
  const text = fs.readFileSync(absolute, 'utf8').replace(/^\uFEFF/, '');
  const wanted = new Set([...schema.typesByName.keys(), ...schema.customTypes.keys()]);
  const types = {};
  let current = null;
  let inFields = false;
  const declaration = /^(?:public|private|protected|internal)(?:\s+(?:sealed|abstract|static|readonly|partial|ref))*\s+(?:class|struct)\s+([^\s:]+)(?:\s*:\s*([^\r\n]+))?/;
  const fieldPattern = /^\s*(public|private|protected|internal)\s+((?:(?:static|readonly|const|volatile|new)\s+)*)(.+?)\s+([^\s;]+);\s*\/\/\s*(0x[0-9a-f]+)/i;
  for (const line of text.split(/\r?\n/)) {
    const declarationMatch = declaration.exec(line);
    if (declarationMatch) {
      const fullName = declarationMatch[1];
      current = wanted.has(fullName) ? { fullName, baseType: declarationMatch[2]?.split(',')[0].trim() || null, fields: {} } : null;
      if (current) types[fullName] = current;
      inFields = false;
      continue;
    }
    if (!current) continue;
    if (line.trim() === '// Fields') { inFields = true; continue; }
    if (line.trim() === '// Methods') { inFields = false; continue; }
    if (!inFields) continue;
    const fieldMatch = fieldPattern.exec(line);
    if (!fieldMatch || /(?:^|\s)(?:static|const)(?:\s|$)/.test(fieldMatch[2])) continue;
    current.fields[fieldMatch[4]] = { type: fieldMatch[3].trim(), offset: normalizeHexOffset(fieldMatch[5]) };
  }
  return {
    schema_version: 1,
    source: absolute,
    source_sha256: sha256(Buffer.from(text)),
    type_count: Object.keys(types).length,
    types,
  };
}

function loadDumpLayout(layoutPath, defaultPath) {
  const selected = path.resolve(layoutPath || defaultPath);
  if (!fs.existsSync(selected)) fail(`dump layout not found: ${selected}; run build-layout first`);
  const layout = JSON.parse(fs.readFileSync(selected, 'utf8').replace(/^\uFEFF/, ''));
  if (!layout || typeof layout !== 'object' || !layout.types) fail(`invalid dump layout ${selected}`);
  return { path: selected, layout };
}

function detectJsonFormat(document) {
  if (document && typeof document === 'object' && !Array.isArray(document) && document.actorData && document.class) return 'runtime-json';
  return 'semantic-json';
}

function editableFieldName(type, field) {
  if (field.editableName || field.editable_name) return field.editableName || field.editable_name;
  const duplicates = type.fields.filter((candidate) => candidate.name === field.name);
  if (duplicates.length <= 1) return field.name;
  return `${String(field.declaredBy || type.fullName).split('.').pop()}.${field.name}`;
}

function completeDefaultSemantic(type) {
  const semantic = clone(type.defaultValue || {});
  if (type.typeId !== null && semantic.$tid === undefined) semantic.$tid = type.typeId;
  for (const field of type.fields) {
    const name = editableFieldName(type, field);
    if (!Object.prototype.hasOwnProperty.call(semantic, name) && !Object.prototype.hasOwnProperty.call(semantic, field.name)) {
      semantic[name] = null;
    }
  }
  return semantic;
}

function templateObjectToFields(semantic, type, schema, layout, objectPath = '$template') {
  const result = {};
  for (const [name, item] of Object.entries(semantic)) {
    if (name === '$tid') continue;
    const field = schemaField(type, name);
    if (!field) continue;
    const layoutField = layoutFieldFor(type, field, layout, schema);
    const key = `${displayType(field, layoutField)} ${name}`;
    try {
      result[key] = semanticValueToRuntime(item, field, schema, layout, `${objectPath}.${name}`);
    } catch (error) {
      if (/unknown KFB type ID|unknown object type/.test(error.message)) result[key] = clone(item);
      else throw error;
    }
  }
  return result;
}

function templateScalarTag(field, declaredType, schema) {
  if (field.has_custom_serializer || schema.customTypes.has(declaredType)) return 'String';
  const code = field.type_code || field.typeCode || '';
  return /^(?:Boolean|Byte|SByte|Int16|UInt16|Int32|UInt32|Int64|UInt64|Single|Double|Decimal|Char|String)$/.test(code)
    ? code : directTypeName(declaredType);
}

function templateFieldValue(semantic, type, field) {
  const name = editableFieldName(type, field);
  if (Object.prototype.hasOwnProperty.call(semantic, name)) return semantic[name];
  if (Object.prototype.hasOwnProperty.call(semantic, field.name)) return semantic[field.name];
  return null;
}

function emitTemplateValue(lines, indent, value, declaredType, field, schema) {
  const pad = '  '.repeat(indent);
  if (value === null || value === undefined) { lines.push(`${pad}<Null />`); return; }
  if (field.is_list || field.is_array) {
    const elementType = field.element_type;
    lines.push(`${pad}<List elementType="${xmlEscape(elementType)}">`);
    for (let index = 0; index < (value || []).length; index += 1) {
      lines.push(`${pad}  <Item index="${index}">`);
      const itemField = { name: 'Item', fieldType: elementType, type_code: '', has_custom_serializer: schema.customTypes.has(elementType),
        is_list: false, is_array: false, is_dictionary: false };
      emitTemplateValue(lines, indent + 2, value[index], elementType, itemField, schema);
      lines.push(`${pad}  </Item>`);
    }
    lines.push(`${pad}</List>`);
    return;
  }
  if (field.is_dictionary) {
    lines.push(`${pad}<Dictionary keyType="${xmlEscape(field.key_type)}" valueType="${xmlEscape(field.value_type)}">`);
    let index = 0;
    for (const [key, item] of Object.entries(value || {})) {
      lines.push(`${pad}  <Entry index="${index++}">`, `${pad}    <Key>`);
      const keyField = { name: 'Key', fieldType: field.key_type, type_code: '', has_custom_serializer: schema.customTypes.has(field.key_type),
        is_list: false, is_array: false, is_dictionary: false };
      emitTemplateValue(lines, indent + 3, key, field.key_type, keyField, schema);
      lines.push(`${pad}    </Key>`, `${pad}    <Value>`);
      const valueField = { name: 'Value', fieldType: field.value_type, type_code: '', has_custom_serializer: schema.customTypes.has(field.value_type),
        is_list: false, is_array: false, is_dictionary: false };
      emitTemplateValue(lines, indent + 3, item, field.value_type, valueField, schema);
      lines.push(`${pad}    </Value>`, `${pad}  </Entry>`);
    }
    lines.push(`${pad}</Dictionary>`);
    return;
  }
  if (field.has_custom_serializer || schema.customTypes.has(declaredType) || isPrimitiveType(field, declaredType)) {
    const tag = templateScalarTag(field, declaredType, schema);
    lines.push(`${pad}<${tag}>${xmlEscape(xmlScalar(value))}</${tag}>`);
    return;
  }
  try {
    const childType = typeForSemantic(value, declaredType, schema, '$template');
    emitTemplateObject(lines, indent, value, childType, schema);
  } catch (error) {
    if (!/unknown KFB type ID|unknown object type/.test(error.message)) throw error;
    lines.push(`${pad}<String>${xmlEscape(JSON.stringify(value))}</String>`);
  }
}

function emitTemplateField(lines, indent, value, type, field, schema) {
  const name = editableFieldName(type, field);
  const pad = '  '.repeat(indent);
  lines.push(`${pad}<Field name="${xmlEscape(name)}" declaredType="${xmlEscape(field.fieldType)}">`);
  emitTemplateValue(lines, indent + 1, value, field.fieldType, field, schema);
  lines.push(`${pad}</Field>`);
}

function emitTemplateObject(lines, indent, semantic, type, schema) {
  const pad = '  '.repeat(indent);
  lines.push(`${pad}<KFBObject kfbType="${xmlEscape(type.fullName)}">`);
  for (const field of type.fields) emitTemplateField(lines, indent + 1, templateFieldValue(semantic, type, field), type, field, schema);
  lines.push(`${pad}</KFBObject>`);
}

function typeTemplateXml(type, semantic, schema) {
  const lines = [];
  if (!isDerivedFrom(type, 'KH.KHScriptData', schema)) {
    emitTemplateObject(lines, 0, semantic, type, schema);
    return `${lines.join('\n')}\n`;
  }
  const attributes = { kfbType: type.fullName };
  const nested = [];
  for (const field of type.fields) {
    const value = templateFieldValue(semantic, type, field);
    const scalar = value !== null && value !== undefined && !field.is_list && !field.is_array && !field.is_dictionary &&
      (field.has_custom_serializer || schema.customTypes.has(field.fieldType) || isPrimitiveType(field));
    if (scalar) attributes[editableFieldName(type, field)] = xmlScalar(value);
    else nested.push({ field, value });
  }
  const attrs = Object.entries(attributes).map(([name, value]) => ` ${name}="${xmlEscape(value)}"`).join('');
  if (!nested.length) return `<KHScriptData${attrs} />\n`;
  lines.push(`<KHScriptData${attrs}>`);
  for (const { field, value } of nested) emitTemplateField(lines, 1, value, type, field, schema);
  lines.push('</KHScriptData>');
  return `${lines.join('\n')}\n`;
}

function buildSchemaTemplates(rawSchema, schema, layout) {
  const output = clone(rawSchema);
  output.template_format_version = 1;
  output.editable_json_format = FORMAT_NAME;
  output.editable_field_syntax = '<display_type> <editable_name>; no runtime offset suffix';
  let success = 0;
  let failures = 0;
  for (const rawType of output.types || []) {
    const type = schema.typesByName.get(rawType.full_name);
    if (!type) continue;
    try {
      for (let index = 0; index < (rawType.fields || []).length; index += 1) {
        const field = type.fields[index];
        const rawField = rawType.fields[index];
        rawField.display_type = displayType(field, layoutFieldFor(type, field, layout, schema));
        rawField.editable_name = editableFieldName(type, field);
        field.displayType = rawField.display_type;
        field.editableName = rawField.editable_name;
      }
      const semantic = completeDefaultSemantic(type);
      rawType.template_json = { [type.fullName]: templateObjectToFields(semantic, type, schema, layout) };
      rawType.template_xml = typeTemplateXml(type, semantic, schema);
      rawType.template_status = 'ok';
      rawType.template_error = null;
      success += 1;
    } catch (error) {
      rawType.template_json = null;
      rawType.template_xml = null;
      rawType.template_status = 'error';
      rawType.template_error = error.message;
      failures += 1;
    }
  }
  output.template_count = success;
  output.template_failure_count = failures;
  return output;
}

module.exports = {
  FORMAT_NAME,
  LEGACY_FORMAT_NAME,
  buildDumpLayout,
  loadDumpLayout,
  semanticToRuntimeJson,
  runtimeJsonToSemantic,
  semanticToLegacyXml,
  legacyXmlToSemantic,
  buildSchemaTemplates,
  detectJsonFormat,
  parseXml,
};
