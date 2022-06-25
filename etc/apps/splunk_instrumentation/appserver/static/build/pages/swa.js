/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 1098);
/******/ })
/************************************************************************/
/******/ ({

/***/ 1066:
/***/ (function(module, exports, __webpack_require__) {

var parent = __webpack_require__(1067);

module.exports = parent;


/***/ }),

/***/ 1067:
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(1068);
var path = __webpack_require__(542);

module.exports = path.Object.assign;


/***/ }),

/***/ 1068:
/***/ (function(module, exports, __webpack_require__) {

var $ = __webpack_require__(519);
var assign = __webpack_require__(1091);

// `Object.assign` method
// https://tc39.es/ecma262/#sec-object.assign
// eslint-disable-next-line es/no-object-assign -- required for testing
$({ target: 'Object', stat: true, forced: Object.assign !== assign }, {
  assign: assign
});


/***/ }),

/***/ 1069:
/***/ (function(module, exports, __webpack_require__) {

var isObject = __webpack_require__(111);
var isSymbol = __webpack_require__(527);
var getMethod = __webpack_require__(1072);
var ordinaryToPrimitive = __webpack_require__(1075);
var wellKnownSymbol = __webpack_require__(1076);

var TO_PRIMITIVE = wellKnownSymbol('toPrimitive');

// `ToPrimitive` abstract operation
// https://tc39.es/ecma262/#sec-toprimitive
module.exports = function (input, pref) {
  if (!isObject(input) || isSymbol(input)) return input;
  var exoticToPrim = getMethod(input, TO_PRIMITIVE);
  var result;
  if (exoticToPrim) {
    if (pref === undefined) pref = 'default';
    result = exoticToPrim.call(input, pref);
    if (!isObject(result) || isSymbol(result)) return result;
    throw TypeError("Can't convert object to primitive value");
  }
  if (pref === undefined) pref = 'number';
  return ordinaryToPrimitive(input, pref);
};


/***/ }),

/***/ 1070:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);
var userAgent = __webpack_require__(1071);

var process = global.process;
var Deno = global.Deno;
var versions = process && process.versions || Deno && Deno.version;
var v8 = versions && versions.v8;
var match, version;

if (v8) {
  match = v8.split('.');
  version = match[0] < 4 ? 1 : match[0] + match[1];
} else if (userAgent) {
  match = userAgent.match(/Edge\/(\d+)/);
  if (!match || match[1] >= 74) {
    match = userAgent.match(/Chrome\/(\d+)/);
    if (match) version = match[1];
  }
}

module.exports = version && +version;


/***/ }),

/***/ 1071:
/***/ (function(module, exports, __webpack_require__) {

var getBuiltIn = __webpack_require__(203);

module.exports = getBuiltIn('navigator', 'userAgent') || '';


/***/ }),

/***/ 1072:
/***/ (function(module, exports, __webpack_require__) {

var aCallable = __webpack_require__(1073);

// `GetMethod` abstract operation
// https://tc39.es/ecma262/#sec-getmethod
module.exports = function (V, P) {
  var func = V[P];
  return func == null ? undefined : aCallable(func);
};


/***/ }),

/***/ 1073:
/***/ (function(module, exports, __webpack_require__) {

var isCallable = __webpack_require__(61);
var tryToString = __webpack_require__(1074);

// `Assert: IsCallable(argument) is true`
module.exports = function (argument) {
  if (isCallable(argument)) return argument;
  throw TypeError(tryToString(argument) + ' is not a function');
};


/***/ }),

/***/ 1074:
/***/ (function(module, exports) {

module.exports = function (argument) {
  try {
    return String(argument);
  } catch (error) {
    return 'Object';
  }
};


/***/ }),

/***/ 1075:
/***/ (function(module, exports, __webpack_require__) {

var isCallable = __webpack_require__(61);
var isObject = __webpack_require__(111);

// `OrdinaryToPrimitive` abstract operation
// https://tc39.es/ecma262/#sec-ordinarytoprimitive
module.exports = function (input, pref) {
  var fn, val;
  if (pref === 'string' && isCallable(fn = input.toString) && !isObject(val = fn.call(input))) return val;
  if (isCallable(fn = input.valueOf) && !isObject(val = fn.call(input))) return val;
  if (pref !== 'string' && isCallable(fn = input.toString) && !isObject(val = fn.call(input))) return val;
  throw TypeError("Can't convert object to primitive value");
};


/***/ }),

/***/ 1076:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);
var shared = __webpack_require__(530);
var has = __webpack_require__(78);
var uid = __webpack_require__(532);
var NATIVE_SYMBOL = __webpack_require__(529);
var USE_SYMBOL_AS_UID = __webpack_require__(528);

var WellKnownSymbolsStore = shared('wks');
var Symbol = global.Symbol;
var createWellKnownSymbol = USE_SYMBOL_AS_UID ? Symbol : Symbol && Symbol.withoutSetter || uid;

module.exports = function (name) {
  if (!has(WellKnownSymbolsStore, name) || !(NATIVE_SYMBOL || typeof WellKnownSymbolsStore[name] == 'string')) {
    if (NATIVE_SYMBOL && has(Symbol, name)) {
      WellKnownSymbolsStore[name] = Symbol[name];
    } else {
      WellKnownSymbolsStore[name] = createWellKnownSymbol('Symbol.' + name);
    }
  } return WellKnownSymbolsStore[name];
};


/***/ }),

/***/ 1077:
/***/ (function(module, exports) {

module.exports = false;


/***/ }),

/***/ 1078:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);
var isObject = __webpack_require__(111);

var document = global.document;
// typeof document.createElement is 'object' in old IE
var EXISTS = isObject(document) && isObject(document.createElement);

module.exports = function (it) {
  return EXISTS ? document.createElement(it) : {};
};


/***/ }),

/***/ 1079:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);
var isCallable = __webpack_require__(61);
var has = __webpack_require__(78);
var createNonEnumerableProperty = __webpack_require__(206);
var setGlobal = __webpack_require__(205);
var inspectSource = __webpack_require__(536);
var InternalStateModule = __webpack_require__(1080);
var CONFIGURABLE_FUNCTION_NAME = __webpack_require__(1083).CONFIGURABLE;

var getInternalState = InternalStateModule.get;
var enforceInternalState = InternalStateModule.enforce;
var TEMPLATE = String(String).split('String');

(module.exports = function (O, key, value, options) {
  var unsafe = options ? !!options.unsafe : false;
  var simple = options ? !!options.enumerable : false;
  var noTargetGet = options ? !!options.noTargetGet : false;
  var name = options && options.name !== undefined ? options.name : key;
  var state;
  if (isCallable(value)) {
    if (String(name).slice(0, 7) === 'Symbol(') {
      name = '[' + String(name).replace(/^Symbol\(([^)]*)\)/, '$1') + ']';
    }
    if (!has(value, 'name') || (CONFIGURABLE_FUNCTION_NAME && value.name !== name)) {
      createNonEnumerableProperty(value, 'name', name);
    }
    state = enforceInternalState(value);
    if (!state.source) {
      state.source = TEMPLATE.join(typeof name == 'string' ? name : '');
    }
  }
  if (O === global) {
    if (simple) O[key] = value;
    else setGlobal(key, value);
    return;
  } else if (!unsafe) {
    delete O[key];
  } else if (!noTargetGet && O[key]) {
    simple = true;
  }
  if (simple) O[key] = value;
  else createNonEnumerableProperty(O, key, value);
// add fake Function#toString for correct work wrapped methods / constructors with methods like LoDash isNative
})(Function.prototype, 'toString', function toString() {
  return isCallable(this) && getInternalState(this).source || inspectSource(this);
});


/***/ }),

/***/ 1080:
/***/ (function(module, exports, __webpack_require__) {

var NATIVE_WEAK_MAP = __webpack_require__(1081);
var global = __webpack_require__(51);
var isObject = __webpack_require__(111);
var createNonEnumerableProperty = __webpack_require__(206);
var objectHas = __webpack_require__(78);
var shared = __webpack_require__(204);
var sharedKey = __webpack_require__(1082);
var hiddenKeys = __webpack_require__(537);

var OBJECT_ALREADY_INITIALIZED = 'Object already initialized';
var WeakMap = global.WeakMap;
var set, get, has;

var enforce = function (it) {
  return has(it) ? get(it) : set(it, {});
};

var getterFor = function (TYPE) {
  return function (it) {
    var state;
    if (!isObject(it) || (state = get(it)).type !== TYPE) {
      throw TypeError('Incompatible receiver, ' + TYPE + ' required');
    } return state;
  };
};

if (NATIVE_WEAK_MAP || shared.state) {
  var store = shared.state || (shared.state = new WeakMap());
  var wmget = store.get;
  var wmhas = store.has;
  var wmset = store.set;
  set = function (it, metadata) {
    if (wmhas.call(store, it)) throw new TypeError(OBJECT_ALREADY_INITIALIZED);
    metadata.facade = it;
    wmset.call(store, it, metadata);
    return metadata;
  };
  get = function (it) {
    return wmget.call(store, it) || {};
  };
  has = function (it) {
    return wmhas.call(store, it);
  };
} else {
  var STATE = sharedKey('state');
  hiddenKeys[STATE] = true;
  set = function (it, metadata) {
    if (objectHas(it, STATE)) throw new TypeError(OBJECT_ALREADY_INITIALIZED);
    metadata.facade = it;
    createNonEnumerableProperty(it, STATE, metadata);
    return metadata;
  };
  get = function (it) {
    return objectHas(it, STATE) ? it[STATE] : {};
  };
  has = function (it) {
    return objectHas(it, STATE);
  };
}

module.exports = {
  set: set,
  get: get,
  has: has,
  enforce: enforce,
  getterFor: getterFor
};


/***/ }),

/***/ 1081:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);
var isCallable = __webpack_require__(61);
var inspectSource = __webpack_require__(536);

var WeakMap = global.WeakMap;

module.exports = isCallable(WeakMap) && /native code/.test(inspectSource(WeakMap));


/***/ }),

/***/ 1082:
/***/ (function(module, exports, __webpack_require__) {

var shared = __webpack_require__(530);
var uid = __webpack_require__(532);

var keys = shared('keys');

module.exports = function (key) {
  return keys[key] || (keys[key] = uid(key));
};


/***/ }),

/***/ 1083:
/***/ (function(module, exports, __webpack_require__) {

var DESCRIPTORS = __webpack_require__(85);
var has = __webpack_require__(78);

var FunctionPrototype = Function.prototype;
// eslint-disable-next-line es/no-object-getownpropertydescriptor -- safe
var getDescriptor = DESCRIPTORS && Object.getOwnPropertyDescriptor;

var EXISTS = has(FunctionPrototype, 'name');
// additional protection from minified / mangled / dropped function names
var PROPER = EXISTS && (function something() { /* empty */ }).name === 'something';
var CONFIGURABLE = EXISTS && (!DESCRIPTORS || (DESCRIPTORS && getDescriptor(FunctionPrototype, 'name').configurable));

module.exports = {
  EXISTS: EXISTS,
  PROPER: PROPER,
  CONFIGURABLE: CONFIGURABLE
};


/***/ }),

/***/ 1084:
/***/ (function(module, exports, __webpack_require__) {

var has = __webpack_require__(78);
var ownKeys = __webpack_require__(1085);
var getOwnPropertyDescriptorModule = __webpack_require__(520);
var definePropertyModule = __webpack_require__(534);

module.exports = function (target, source) {
  var keys = ownKeys(source);
  var defineProperty = definePropertyModule.f;
  var getOwnPropertyDescriptor = getOwnPropertyDescriptorModule.f;
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (!has(target, key)) defineProperty(target, key, getOwnPropertyDescriptor(source, key));
  }
};


/***/ }),

/***/ 1085:
/***/ (function(module, exports, __webpack_require__) {

var getBuiltIn = __webpack_require__(203);
var getOwnPropertyNamesModule = __webpack_require__(1086);
var getOwnPropertySymbolsModule = __webpack_require__(541);
var anObject = __webpack_require__(535);

// all object keys, includes non-enumerable and symbols
module.exports = getBuiltIn('Reflect', 'ownKeys') || function ownKeys(it) {
  var keys = getOwnPropertyNamesModule.f(anObject(it));
  var getOwnPropertySymbols = getOwnPropertySymbolsModule.f;
  return getOwnPropertySymbols ? keys.concat(getOwnPropertySymbols(it)) : keys;
};


/***/ }),

/***/ 1086:
/***/ (function(module, exports, __webpack_require__) {

var internalObjectKeys = __webpack_require__(538);
var enumBugKeys = __webpack_require__(540);

var hiddenKeys = enumBugKeys.concat('length', 'prototype');

// `Object.getOwnPropertyNames` method
// https://tc39.es/ecma262/#sec-object.getownpropertynames
// eslint-disable-next-line es/no-object-getownpropertynames -- safe
exports.f = Object.getOwnPropertyNames || function getOwnPropertyNames(O) {
  return internalObjectKeys(O, hiddenKeys);
};


/***/ }),

/***/ 1087:
/***/ (function(module, exports, __webpack_require__) {

var toIndexedObject = __webpack_require__(202);
var toLength = __webpack_require__(1088);
var toAbsoluteIndex = __webpack_require__(1089);

// `Array.prototype.{ indexOf, includes }` methods implementation
var createMethod = function (IS_INCLUDES) {
  return function ($this, el, fromIndex) {
    var O = toIndexedObject($this);
    var length = toLength(O.length);
    var index = toAbsoluteIndex(fromIndex, length);
    var value;
    // Array#includes uses SameValueZero equality algorithm
    // eslint-disable-next-line no-self-compare -- NaN check
    if (IS_INCLUDES && el != el) while (length > index) {
      value = O[index++];
      // eslint-disable-next-line no-self-compare -- NaN check
      if (value != value) return true;
    // Array#indexOf ignores holes, Array#includes - not
    } else for (;length > index; index++) {
      if ((IS_INCLUDES || index in O) && O[index] === el) return IS_INCLUDES || index || 0;
    } return !IS_INCLUDES && -1;
  };
};

module.exports = {
  // `Array.prototype.includes` method
  // https://tc39.es/ecma262/#sec-array.prototype.includes
  includes: createMethod(true),
  // `Array.prototype.indexOf` method
  // https://tc39.es/ecma262/#sec-array.prototype.indexof
  indexOf: createMethod(false)
};


/***/ }),

/***/ 1088:
/***/ (function(module, exports, __webpack_require__) {

var toInteger = __webpack_require__(539);

var min = Math.min;

// `ToLength` abstract operation
// https://tc39.es/ecma262/#sec-tolength
module.exports = function (argument) {
  return argument > 0 ? min(toInteger(argument), 0x1FFFFFFFFFFFFF) : 0; // 2 ** 53 - 1 == 9007199254740991
};


/***/ }),

/***/ 1089:
/***/ (function(module, exports, __webpack_require__) {

var toInteger = __webpack_require__(539);

var max = Math.max;
var min = Math.min;

// Helper for a popular repeating case of the spec:
// Let integer be ? ToInteger(index).
// If integer < 0, let result be max((length + integer), 0); else let result be min(integer, length).
module.exports = function (index, length) {
  var integer = toInteger(index);
  return integer < 0 ? max(integer + length, 0) : min(integer, length);
};


/***/ }),

/***/ 1090:
/***/ (function(module, exports, __webpack_require__) {

var fails = __webpack_require__(86);
var isCallable = __webpack_require__(61);

var replacement = /#|\.prototype\./;

var isForced = function (feature, detection) {
  var value = data[normalize(feature)];
  return value == POLYFILL ? true
    : value == NATIVE ? false
    : isCallable(detection) ? fails(detection)
    : !!detection;
};

var normalize = isForced.normalize = function (string) {
  return String(string).replace(replacement, '.').toLowerCase();
};

var data = isForced.data = {};
var NATIVE = isForced.NATIVE = 'N';
var POLYFILL = isForced.POLYFILL = 'P';

module.exports = isForced;


/***/ }),

/***/ 1091:
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var DESCRIPTORS = __webpack_require__(85);
var fails = __webpack_require__(86);
var objectKeys = __webpack_require__(1092);
var getOwnPropertySymbolsModule = __webpack_require__(541);
var propertyIsEnumerableModule = __webpack_require__(521);
var toObject = __webpack_require__(531);
var IndexedObject = __webpack_require__(523);

// eslint-disable-next-line es/no-object-assign -- safe
var $assign = Object.assign;
// eslint-disable-next-line es/no-object-defineproperty -- required for testing
var defineProperty = Object.defineProperty;

// `Object.assign` method
// https://tc39.es/ecma262/#sec-object.assign
module.exports = !$assign || fails(function () {
  // should have correct order of operations (Edge bug)
  if (DESCRIPTORS && $assign({ b: 1 }, $assign(defineProperty({}, 'a', {
    enumerable: true,
    get: function () {
      defineProperty(this, 'b', {
        value: 3,
        enumerable: false
      });
    }
  }), { b: 2 })).b !== 1) return true;
  // should work with symbols and should have deterministic property order (V8 bug)
  var A = {};
  var B = {};
  // eslint-disable-next-line es/no-symbol -- safe
  var symbol = Symbol();
  var alphabet = 'abcdefghijklmnopqrst';
  A[symbol] = 7;
  alphabet.split('').forEach(function (chr) { B[chr] = chr; });
  return $assign({}, A)[symbol] != 7 || objectKeys($assign({}, B)).join('') != alphabet;
}) ? function assign(target, source) { // eslint-disable-line no-unused-vars -- required for `.length`
  var T = toObject(target);
  var argumentsLength = arguments.length;
  var index = 1;
  var getOwnPropertySymbols = getOwnPropertySymbolsModule.f;
  var propertyIsEnumerable = propertyIsEnumerableModule.f;
  while (argumentsLength > index) {
    var S = IndexedObject(arguments[index++]);
    var keys = getOwnPropertySymbols ? objectKeys(S).concat(getOwnPropertySymbols(S)) : objectKeys(S);
    var length = keys.length;
    var j = 0;
    var key;
    while (length > j) {
      key = keys[j++];
      if (!DESCRIPTORS || propertyIsEnumerable.call(S, key)) T[key] = S[key];
    }
  } return T;
} : $assign;


/***/ }),

/***/ 1092:
/***/ (function(module, exports, __webpack_require__) {

var internalObjectKeys = __webpack_require__(538);
var enumBugKeys = __webpack_require__(540);

// `Object.keys` method
// https://tc39.es/ecma262/#sec-object.keys
// eslint-disable-next-line es/no-object-keys -- safe
module.exports = Object.keys || function keys(O) {
  return internalObjectKeys(O, enumBugKeys);
};


/***/ }),

/***/ 1093:
/***/ (function(module, exports, __webpack_require__) {

var parent = __webpack_require__(1094);

module.exports = parent;


/***/ }),

/***/ 1094:
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(1095);
var path = __webpack_require__(542);

module.exports = path.Array.isArray;


/***/ }),

/***/ 1095:
/***/ (function(module, exports, __webpack_require__) {

var $ = __webpack_require__(519);
var isArray = __webpack_require__(1096);

// `Array.isArray` method
// https://tc39.es/ecma262/#sec-array.isarray
$({ target: 'Array', stat: true }, {
  isArray: isArray
});


/***/ }),

/***/ 1096:
/***/ (function(module, exports, __webpack_require__) {

var classof = __webpack_require__(524);

// `IsArray` abstract operation
// https://tc39.es/ecma262/#sec-isarray
// eslint-disable-next-line es/no-array-isarray -- safe
module.exports = Array.isArray || function isArray(argument) {
  return classof(argument) == 'Array';
};


/***/ }),

/***/ 1098:
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);

// EXTERNAL MODULE: ./node_modules/core-js/features/object/assign.js
var object_assign = __webpack_require__(568);
var assign_default = /*#__PURE__*/__webpack_require__.n(object_assign);

// EXTERNAL MODULE: ./node_modules/core-js/features/array/is-array.js
var is_array = __webpack_require__(569);
var is_array_default = /*#__PURE__*/__webpack_require__.n(is_array);

// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/core/monkeyPatch.es



function monkeyPatch(obj, field, value) {
  if (typeof obj[field] === 'undefined') {
    obj[field] = value;
  }
}

monkeyPatch(Object, 'assign', assign_default.a);
monkeyPatch(Array, 'isArray', is_array_default.a);
// EXTERNAL MODULE: ./node_modules/@babel/runtime/helpers/classCallCheck.js
var classCallCheck = __webpack_require__(12);
var classCallCheck_default = /*#__PURE__*/__webpack_require__.n(classCallCheck);

// EXTERNAL MODULE: ./node_modules/@babel/runtime/helpers/createClass.js
var createClass = __webpack_require__(13);
var createClass_default = /*#__PURE__*/__webpack_require__.n(createClass);

// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/constants.es
var constants = {};
/**
 * GENERAL SWA SETTINGS
 * */

constants.CACHE_NAME = 'mintjs:cache';
constants.MAX_QUEUE_SIZE = 10;
constants.MINT_UUID = '123';
constants.COOKIE_CSRF_REGEX = /splunkweb_csrf_token_[0-9]+=([^;]*)/; // Key to save experience id in cookie

constants.EXPERIENCE_ID_KEY = 'experience_id';
constants.COOKIE_EXPERIENCE_ID_REGEX = /experience_id=([^;]*)/; // Key to save CSRF token in cookie as future references

constants.SAVED_TOKEN_KEY = 'token_key';
constants.COOKIE_SAVED_TOKEN_KEY_REGEX = /token_key=([^;]*)/; // Can't rely on $C existing if we're loaded in a 3rd-party
// page (perhaps served by a custom controller), so check first.

constants.LOCALE = window.$C && window.$C.LOCALE; // If we can't find the locale, we're in a strange place.
// We'll use this to skip certain logic that requires a familiar
// page context as usually provided by splunkweb.

constants.FOREIGN_PAGE_CONTEXT = !constants.LOCALE; // Capture Groups: 1 = app name, 2 = page string
// Page string will exclude any ?query=params or #anchors from the URL

constants.APP_PAGE_DATA_REGEXP = new RegExp("".concat(constants.LOCALE, "/app/([^#?/]+)/([^#?]*)")); // Capture Groups: 1 = page string - which is the location string

constants.HELP_PAGE_DATA_REGEXP = new RegExp("".concat(constants.LOCALE, "/help\\?(?:.+&)?location=([^&]*)")); // Capture Groups: 1 = page string
// System pages are all those not under the /help/ or /app/ namespaces

constants.SYSTEM_PAGE_DATA_REGEXP = new RegExp("".concat(constants.LOCALE, "/([^#?]*)"));
constants.SYSTEM_APP_NAME = '$SPLUNK_PLATFORM'; // Capture Groups: 1 = page string prefix, 2 = username, 3 = page string suffix
// Capture group 2 should be excluded if this regexp matches a URL to be reported.
// If editing, be mindful the capture group protocol listed above.
//  - You can use (?:non-capturing-groups) to group without capturing,
//    and thus avoid affecting the protocol.

constants.USERNAME_OBSCURE_REGEXP = new RegExp( // Match the locale segment
"".concat(constants.LOCALE, "/") // Match group #1 - the page string preceding the username
+ '(manager/[^/]+/authentication/(?:users|changepassword)/)' // Match group #2 - the username segment
+ '([^/#?]+)' // Match group #3 - the rest of the page string excluding any query params or anchors.
// Should match the empty string in case of no trailing segment
+ '(/?[^#?]*)');
/**
 * DEV MODE OPTIONS
 * */

/**
 * Enables dev mode.
 */

constants.DEV_MODE = false;
/**
 * Enables logging
 * @type {boolean}
 */

constants.ENABLE_LOGGING = false;
/**
 * Logs event sending on dev mode.
 * @constructor
 */

constants.LOG = function () {
  if (constants.DEV_MODE || constants.ENABLE_LOGGING) {
    var _window;

    (_window = window).console.apply(_window, arguments);
  }
};
/**
/* HELPER FUNCTIONS
/**
/**
 * Define a function that returns stringified data.
 * (events) => {
 *     return events.toString();
 * }
 *
 * Set to 'CDS' to use internal function to bundle data for CDS. Default.
 * Set to null to use basic stringify.
 *
 * @param events
 * @returns {string|*}
 * @constructor
 */


constants.BUNDLE_DATA_FUNCTION = 'CDS';
/**
 * Parses a JSON string to an Event.
 * @param key
 * @param val
 * @returns {*}
 * @constructor
 */

/* constants.EVENT_PARSER = (key, val) => {
    if (typeof(val) === 'object' && val.__type == "Event") {
        return new Event(val);
    }
    return val;
   }  */

/**
 * EXPORT
 * */

/* harmony default export */ var SWA_constants = ({
  cacheKey: 'swa_js_recovery',
  queueFailureMax: 200,
  baseURL: constants.BASE_URL,
  bundleDataFunction: constants.BUNDLE_DATA_FUNCTION,
  devMode: constants.DEV_MODE,
  devURL: constants.DEV_URL,
  // Set null to not send data
  log: constants.LOG,
  logging: constants.ENABLE_LOGGING,
  maxQueueSize: constants.MAX_QUEUE_SIZE,
  mintUuid: constants.MINT_UUID,
  experienceIDKey: constants.EXPERIENCE_ID_KEY,
  cookieCSRFRegex: constants.COOKIE_CSRF_REGEX,
  cookieExperienceIDRegex: constants.COOKIE_EXPERIENCE_ID_REGEX,
  cookieSavedTokenKeyRegex: constants.COOKIE_SAVED_TOKEN_KEY_REGEX,
  savedTokenKey: constants.SAVED_TOKEN_KEY,
  LOCALE: constants.LOCALE,
  FOREIGN_PAGE_CONTEXT: constants.FOREIGN_PAGE_CONTEXT,
  APP_PAGE_DATA_REGEXP: constants.APP_PAGE_DATA_REGEXP,
  HELP_PAGE_DATA_REGEXP: constants.HELP_PAGE_DATA_REGEXP,
  SYSTEM_PAGE_DATA_REGEXP: constants.SYSTEM_PAGE_DATA_REGEXP,
  USERNAME_OBSCURE_REGEXP: constants.USERNAME_OBSCURE_REGEXP,
  SYSTEM_APP_NAME: constants.SYSTEM_APP_NAME
});
// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/services/Dispatcher.es


var API_VERSION = '1.0';

var Dispatcher_Dispatcher = /*#__PURE__*/function () {
  /** **************************************************************************************
   * PUBLIC API                                                                            *
   ****************************************************************************************
   * */

  /**
   * @param options - Pass in SWACore options to construct dispatcher
   */
  function Dispatcher(options) {
    classCallCheck_default()(this, Dispatcher);

    this._options = options;
  }
  /**
   * Send data to CDS
   *
   * @param {Event[]} events - Array of Events to send
   * @param {boolean} final - Sends all data
   * @returns {Promise} Data sent or error
   */


  createClass_default()(Dispatcher, [{
    key: "sendData",
    value: function sendData() {
      var _this = this;

      var events = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : [{}];

      var _final = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      var url = this._buildURL(events);

      var data = this.bundleData(events);

      this._options.log('Sending Data:', data);

      return new Promise(function (resolve, reject) {
        if (url && data) {
          var onFail = function onFail(status, text) {
            reject(new Error({
              status: status,
              statusText: text,
              events: events
            }));
          };

          if (_final && navigator.sendBeacon) {
            // Uses sendBeacon because asynchronous POST will not work for window.unload.
            var blob = new Blob([data], {
              type: 'application/json'
            });

            if (navigator.sendBeacon(url, blob)) {
              resolve({
                response: 'success',
                data: data
              });
            } else {
              onFail(400, 'Error sending events.');
            }
          } else {
            var xhr = new XMLHttpRequest();

            var headers = _this._buildHeaders();

            xhr.open('post', url);

            xhr.onload = function onload() {
              if (this.status >= 200 && this.status < 300) {
                resolve({
                  response: xhr.response,
                  data: data
                });
              } else {
                onFail(this.status, xhr.statusText);
              }
            };

            xhr.onerror = function onerror() {
              onFail(this.status, xhr.statusText);
            };

            if (url[0] === '/') {
              _this.addCSRFToHeader(headers);
            }

            if (headers) {
              Object.keys(headers).forEach(function (key) {
                xhr.setRequestHeader(key, headers[key]);
              });
            }

            try {
              xhr.send(data);
            } catch (e) {
              onFail(0, e);
            }
          }
        } else {
          var message = 'No Data Sent: URL not set.';
          reject(new Error(message));
        }
      });
    }
  }, {
    key: "addCSRFToHeader",
    value: function addCSRFToHeader(headers) {
      function getCookie(name) {
        var v = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
        return v ? v[2] : null;
      }

      var cookieName = 'splunkweb_csrf_token_' + window.$C.MRSPARKLE_PORT_NUMBER;
      var csrfToken = getCookie(cookieName);
      headers['X-Requested-With'] = 'XMLHttpRequest';
      headers['X-Splunk-Form-Key'] = csrfToken;
    }
    /**
     * Formats data into JSON to be sent.
     * @param {Event[]} events - Array of Events to send
     * @returns {string|*} - JSON string of data.
     */

  }, {
    key: "bundleData",
    value: function bundleData() {
      var events = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : [{}];
      var bundleDataFunction = this._options.bundleDataFunction || 'json';

      if (bundleDataFunction instanceof Function) {
        return bundleDataFunction(events);
      }

      if (bundleDataFunction === 'CDS') {
        return this._formatDataForCDS(events);
      }

      if (bundleDataFunction === 'json') {
        return Dispatcher._formatDataForEndpoint(events);
      }

      return JSON.stringify(events);
    }
    /**
     * @returns {string} The API version.
     */

  }, {
    key: "_buildURL",
    value:
    /** ******************************************************************************************
     * PRIVATE FUNCTIONS                                                                         *
     *******************************************************************************************
     * */

    /**
     * Builds URL according to CDS specs
     * @param {object} events
     * @returns {string} The URL
     * @private
     */
    function _buildURL(events) {
      var baseURL = this._options.url;

      if (baseURL && events && baseURL.indexOf('splkmobile') > -1) {
        var errorCount = 0;
        var eventCount = 0;
        (events || []).forEach(function (event) {
          if (event.stacktrace || event.errorHash || event.klass) {
            errorCount += 1;
          } else {
            eventCount += 1;
          }
        });
        baseURL = [baseURL, this._options.MintUUID, errorCount, eventCount].join('/');
      }

      return baseURL;
    }
    /**
     * Builds the headers to send to CDS
     * @param {boolean} sendToHEC
     * @returns {Object} Headers
     * @private
     */

  }, {
    key: "_buildHeaders",
    value: function _buildHeaders() {
      var sendToHEC = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : this._options.sendToHEC;
      var headers = {}; // Setting different headers

      if (sendToHEC) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
        headers.Authorization = 'Splunk '.concat(this._options.token);
      } else {
        headers['Content-Type'] = 'application/json;charset=UTF-8';
        headers['X-Splunk-Mint-Send-CORS'] = true;
      }

      return headers;
    }
    /**
     * Formats data to be sent to Internal Rest Endpoint
     * @param events
     * @returns {object}
     * @private
     */

  }, {
    key: "_formatDataForCDS",
    value:
    /**
     * Formats data to be sent to CDS
     * @param events
     * @returns {string|*}
     * @private
     */
    function _formatDataForCDS(events) {
      var _this2 = this;

      return events.map(function (event) {
        var result = event.toPayload();
        result.version = _this2._options.version;
        var root = {
          sdkVersion: '4.3',
          osVersion: '0',
          event_name: 'Deployment',
          appVersionCode: '3',
          uuid: _this2._options.deploymentID,
          packageName: 'splunk_instrumentation',
          extraData: result,
          session_id: result.experienceID,
          appVersionName: '1'
        };
        return "".concat(JSON.stringify(root) + ['{', parseInt(Dispatcher.getApiVersion(), 10), 'event', event.timestamp].join('^'), "}");
      }).join('');
    }
  }], [{
    key: "getApiVersion",
    value: function getApiVersion() {
      return API_VERSION;
    }
  }, {
    key: "_formatDataForEndpoint",
    value: function _formatDataForEndpoint(events) {
      return JSON.stringify(events.map(function (event) {
        return event.toPayload();
      }).map(function (event) {
        event.type = 'event';
        event.visibility = event.visibility.split(',');
        return event;
      }));
    }
  }]);

  return Dispatcher;
}();


// EXTERNAL MODULE: ./node_modules/@babel/runtime/helpers/defineProperty.js
var defineProperty = __webpack_require__(9);
var defineProperty_default = /*#__PURE__*/__webpack_require__.n(defineProperty);

// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/services/Cache.es




function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); enumerableOnly && (symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; })), keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = null != arguments[i] ? arguments[i] : {}; i % 2 ? ownKeys(Object(source), !0).forEach(function (key) { defineProperty_default()(target, key, source[key]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)) : ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } return target; }

var Cache_Cache = /*#__PURE__*/function () {
  function Cache(options) {
    classCallCheck_default()(this, Cache);

    this._options = _objectSpread(_objectSpread({}, options), {}, {
      cacheKey: 'swa_js_default_cache',
      queueFailureMax: 200
    });
  }

  createClass_default()(Cache, [{
    key: "hashEventIDsInQueue",
    value: function hashEventIDsInQueue(queue) {
      var hash = {};
      queue.forEach(function (item) {
        hash[item.eventID] = true;
      });
      return hash;
    }
  }, {
    key: "save",
    value: function save(data) {
      var queue = this.retrieve();
      var eventIDHash = this.hashEventIDsInQueue(queue);
      data.forEach(function (dto) {
        if (!eventIDHash[dto.eventID]) {
          queue.push(dto);
        }
      });

      this._update(queue);
    }
  }, {
    key: "retrieve",
    value: function retrieve() {
      var data = JSON.parse(localStorage.getItem(this._options.cacheKey)) || {
        queue: []
      };
      return data.queue;
    }
  }, {
    key: "clear",
    value: function clear() {
      this._update([]);
    }
  }, {
    key: "_update",
    value: function _update(queue) {
      while (queue.length > this._options.queueFailureMax) {
        queue.shift();
      }

      try {
        localStorage.setItem(this._options.cacheKey, JSON.stringify({
          queue: queue
        }));
      } catch (e) {
        if (this._options.log) this._options.log('localStorage is full or not available.');
      }
    }
  }]);

  return Cache;
}();


// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/handlers/RecoveryHandler.es
/**
 * Created by adrianj on 11/11/16.
 */

function RecoveryHandler(factory, options) {
  var cache = options.cache || new Cache_Cache();
  var queue = cache.retrieve();
  cache.clear();

  var cacheEvents = function cacheEvents(events) {
    if (events && Array.isArray(events)) {
      options.log('caching events:', events.length);
      cache.save(events);
    }
  };

  options.updateOptions({
    eventRecovery: cacheEvents
  });

  if (queue && queue.length) {
    options.log('flushing from cache:', queue.length);
    queue.push('flush');
    queue.forEach(factory);
  }

  window.addEventListener('beforeunload', function () {
    factory('save');
  }); // flush queue every 30 seconds

  setTimeout(function () {
    return factory('flush');
  }, 30000);
}
// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/handlers/ApiHandler.es
function ApiHandler(factory, options) {
  var queue = window._splunk_metrics_events;

  var push = function push(item) {
    if (item.type === 'config') {
      options.updateOptions(item.data);
    } else {
      factory(item);
    }
  };

  window._splunk_metrics_events = {
    push: push
  };

  if (queue && queue.forEach) {
    queue.forEach(function (item) {
      return push(item);
    });
  }
}
/**
 * plucks all the config event from the queue and updates swa._options
 * before swa starts processing events to allow developers to change the config.
 * @param options
 */

ApiHandler.init = function init(options) {
  // if global does not exist or is not an array with reduce then do nothing.
  if (!window._splunk_metrics_events || !window._splunk_metrics_events.reduce) return;
  var newQueue = [];

  var configs = window._splunk_metrics_events.reduce(function (accumulator, value) {
    if (value.type === 'config') {
      accumulator.push(value);
    } else {
      newQueue.push(value);
    }

    return accumulator;
  }, []);

  window._splunk_metrics_events = newQueue;
  configs.forEach(function (event) {
    return options.updateOptions(event.data);
  });
};
// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/handlers/PageHandler.es
function PageHandler(factory) {
  var event = {
    type: 'pageview'
  };
  return factory(event);
}
// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/models/Event.es




var Event_Event = /*#__PURE__*/function () {
  /**
   * Creates an Event. (All params are required)
   * @param {object} eventData - Event data.
   * @param {string} deploymentID - ID of the Deployment.
   * @param {string} experienceID - ID of the Session.
   * @param {string} userID - ID of the current user.
   * @returns {*}
   */
  function Event(eventData, experienceID, userID, deploymentID, visibility) {
    classCallCheck_default()(this, Event);

    this._type = eventData.type;
    this.data = eventData.data || {};
    this.experienceID = eventData.experienceID || experienceID;
    this.userID = eventData.userID || userID;
    this._timestamp = eventData.timestamp || parseInt(Date.now() / 1000, 10);
    this.visibility = eventData.visibility || visibility;
    this.optInRequired = eventData.optInRequired || 3;
    this.deploymentID = eventData.deploymentID || deploymentID;
    this.splunkVersion = eventData.splunkVersion || window.$C.VERSION_LABEL;
    this.eventID = eventData.eventID || Event._generateExperienceID();

    if (!this.data.app || !this.data.page) {
      var pageData = Event.getPageData(Event.getURL());

      if (!this.data.app) {
        this.data.app = pageData.app;
      }

      if (!this.data.page) {
        this.data.page = pageData.page;
      }
    }

    return this;
  }

  createClass_default()(Event, [{
    key: "toJSON",
    value: function toJSON() {
      return {
        __type: 'Event',
        data: this.data,
        type: this._type,
        timestamp: this._timestamp,
        visibility: this.visibility,
        experienceID: this.experienceID,
        deploymentID: this.deploymentID,
        userID: this.userID,
        eventID: this.eventID,
        splunkVersion: this.splunkVersion,
        optInRequired: this.optInRequired
      };
    }
  }, {
    key: "toPayload",
    value: function toPayload() {
      var result = {};
      result.component = "app.session.".concat(this.type);
      result.data = this.data;
      result.timestamp = this.timestamp;
      result.visibility = this.visibility;
      result.experienceID = this.experienceID;
      result.deploymentID = this.deploymentID;
      result.userID = this.userID;
      result.eventID = this.eventID;
      result.splunkVersion = this.splunkVersion;
      result.optInRequired = this.optInRequired;
      return result;
    }
  }, {
    key: "type",
    get: function get() {
      return this._type;
    }
  }, {
    key: "timestamp",
    get: function get() {
      return this._timestamp;
    }
  }], [{
    key: "getURL",
    value: function getURL() {
      if (window && window.location) {
        return window.location.href;
      }

      return null;
    }
  }, {
    key: "getPageData",
    value: function getPageData(url) {
      var unknown = {
        app: 'UNKNOWN_APP',
        page: 'UNKNOWN_PAGE'
      };

      if (SWA_constants.FOREIGN_PAGE_CONTEXT) {
        // Couldn't find $C, no locale known,
        // no chance of parsing page data.
        // May happen when rendering pages
        // through 3rd party custom controllers.
        return unknown;
      }

      return Event.getHelpPageData(url) || Event.getAppPageData(url) || Event.getSystemPageData(url) || unknown;
    }
  }, {
    key: "getHelpPageData",
    value: function getHelpPageData(url) {
      var match = url.match(SWA_constants.HELP_PAGE_DATA_REGEXP);

      if (match) {
        return {
          app: SWA_constants.SYSTEM_APP_NAME,
          page: "help/".concat(match[1])
        };
      }

      return null;
    }
  }, {
    key: "getAppPageData",
    value: function getAppPageData(url) {
      var match = url.match(SWA_constants.APP_PAGE_DATA_REGEXP);

      if (match) {
        return {
          app: match[1],
          page: match[2]
        };
      }

      return null;
    }
  }, {
    key: "getSystemPageData",
    value: function getSystemPageData(url) {
      var match = url.match(SWA_constants.SYSTEM_PAGE_DATA_REGEXP);

      if (match) {
        var page = match[1];
        var usernameMatch = url.match(SWA_constants.USERNAME_OBSCURE_REGEXP);

        if (usernameMatch) {
          // This regexp found a username in capture group 2,
          // so drop it, and join the prefix & suffix.
          page = "".concat(usernameMatch[1], "$USERNAME").concat(usernameMatch[3]);
        }

        return {
          app: SWA_constants.SYSTEM_APP_NAME,
          page: page
        };
      }

      return null;
    }
  }, {
    key: "isString",
    value: function isString(obj) {
      return Object.prototype.toString.call(obj) === '[object String]';
    }
    /**
     * Checks all params of constructor if defined, else throw an error.
     * @param {object} eventData - Event data.
     * @returns list of errors
     * @private
     */

  }, {
    key: "checkParams",
    value: function checkParams(eventData) {
      var errors = [];

      if (!eventData.type || !Event.isString(eventData.type)) {
        errors.push('type parameter has to be a string');
        return errors;
      }

      return true;
    }
  }, {
    key: "_generateExperienceID",
    value: function _generateExperienceID() {
      function seed() {
        return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
      }

      return "".concat(seed()).concat(seed(), "-").concat(seed(), "-").concat(seed(), "-").concat(seed(), "-").concat(seed()).concat(seed()).concat(seed());
    }
  }]);

  return Event;
}();


// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/services/EventQueue.es




var EventQueue_EventQueue = /*#__PURE__*/function () {
  /**
   * PUBLIC API                                                                          *
   **************************************************************************************
   * */

  /**
   * @param options - Pass in SWACore options to construct event queue
   * @param dispatcher - Pass in dispatcher to send events from queue
   */
  function EventQueue(options, dispatcher) {
    classCallCheck_default()(this, EventQueue);

    this._options = options;
    this._dispatcher = dispatcher;
    this.factory = this.push.bind(this);
    this._events = [];
  }
  /**
   * Adds data into queue. Once queue reaches QUEUE_SIZE, it will send data.
   *
   * all events should format is  { type,  data ,timestamp, date}
   *
   * @param {string} eventType - The type of event.
   * @param {Object} event - Data to push to queue.
   */


  createClass_default()(EventQueue, [{
    key: "push",
    value: function push(pevent) {
      var response;

      var event = this._createEvent(pevent);

      if (!event) {
        return response;
      }

      if (event.type === 'final' || event.type === 'unload' || event.type === 'flush') {
        response = this.flush(event.type);
      } else if (event && event.type === 'save') {
        this._options.eventRecovery(this._events);
      } else {
        this._options.log('Pushing Data To Queue:', event);

        this._events.push(event);

        if (this.getQueueSize() >= this._options.maxQueueSize) {
          response = this._send(this._events);

          this._emptyQueue();
        } else {
          response = Promise.resolve();
        }
      }

      this._options.log('Current Queue:', this._events);

      return response;
    }
    /**
     * Flush out queue and sends all data.
     * @param {string} flush - Type of flush: 'flush' or 'unload'
     */

  }, {
    key: "flush",
    value: function flush(_flush) {
      var response;

      this._options.log("Flushing Queue (".concat(_flush, "):"), this._events);

      if (this.getQueueSize() > 0) {
        if (_flush === 'flush') {
          response = this._send(this._events);
        } else if (_flush === 'final' || _flush === 'unload') {
          // For unload, dispatch remaining data using sendBeacon method
          response = this._send(this._events, true);
        }

        this._emptyQueue();
      } else {
        response = Promise.resolve();
      }

      return response;
    }
    /**
     * @returns {*|Number} Size of the queue
     */

  }, {
    key: "getQueueSize",
    value: function getQueueSize() {
      return this._events.length;
    }
    /** *********************************************************************************
     * PRIVATE FUNCTIONS
     ***********************************************************************************
     */

  }, {
    key: "_createEvent",
    value: function _createEvent(pevent) {
      var event = typeof pevent === 'string' ? {
        type: pevent
      } : pevent;
      var er = Event_Event.checkParams(event);

      if (er.length > 0) {
        this._options.log('Cant create Event', er);

        return false;
      }

      return new Event_Event(event, this._options.experienceID, this._options.userID, this._options.deploymentID, this._options.visibility);
    }
    /**
     * Sends data to dispatcher.
     * @param {Object} data - Data to send.
     * @private
     */

  }, {
    key: "_send",
    value: function _send(data) {
      var _this = this;

      var _final = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      return this._dispatcher.sendData(data, _final)["catch"](function (error) {
        _this._options.eventRecovery(error.events);
      });
    }
    /**
     * Empties the queue.
     * @private
     */

  }, {
    key: "_emptyQueue",
    value: function _emptyQueue() {
      this._events = [];
    }
  }]);

  return EventQueue;
}();


// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/handlers/SessionHandler.es
var NA = 'not available';
var newSession = null;

function strip(string, symb) {
  var end = string.indexOf(symb);

  if (end !== -1) {
    return string.substring(0, end);
  }

  return string;
} // Getting value from document.cookie


function getValueFromCookie(regex) {
  var token = document.cookie;
  var match = token.match(regex) || [];
  return match[1];
}
function setValueToCookie(key, value) {
  document.cookie = "".concat(key, "=").concat(value, "; path=/");
}
function getOsInfo(userAgent) {
  if (!userAgent) {
    return {
      os: NA,
      osVersion: NA
    };
  }

  var osName = '';
  var osVersion = '';
  /*
  s: os name
  r: regex for searching
  */

  var osInfo = [{
    s: 'Windows 10',
    r: /(Windows 10.0|Windows NT 10.0)/
  }, {
    s: 'Windows 8.1',
    r: /(Windows 8.1|Windows NT 6.3)/
  }, {
    s: 'Windows 8',
    r: /(Windows 8|Windows NT 6.2)/
  }, {
    s: 'Windows 7',
    r: /(Windows 7|Windows NT 6.1)/
  }, {
    s: 'Windows Vista',
    r: /Windows NT 6.0/
  }, {
    s: 'Windows Server 2003',
    r: /Windows NT 5.2/
  }, {
    s: 'Windows XP',
    r: /(Windows NT 5.1|Windows XP)/
  }, {
    s: 'Windows 2000',
    r: /(Windows NT 5.0|Windows 2000)/
  }, {
    s: 'Windows ME',
    r: /(Win 9x 4.90|Windows ME)/
  }, {
    s: 'Windows 98',
    r: /(Windows 98|Win98)/
  }, {
    s: 'Windows 95',
    r: /(Windows 95|Win95|Windows_95)/
  }, {
    s: 'Windows NT 4.0',
    r: /(Windows NT 4.0|WinNT4.0|WinNT|Windows NT)/
  }, {
    s: 'Windows CE',
    r: /Windows CE/
  }, {
    s: 'Windows 3.11',
    r: /Win16/
  }, {
    s: 'Android',
    r: /Android/
  }, {
    s: 'Open BSD',
    r: /OpenBSD/
  }, {
    s: 'Sun OS',
    r: /SunOS/
  }, {
    s: 'Ubuntu',
    r: /Ubuntu/
  }, {
    s: 'Linux',
    r: /(Linux|X11)/
  }, {
    s: 'iOS',
    r: /(iPhone|iPad|iPod)/
  }, {
    s: 'Mac OS X',
    r: /Mac OS X/
  }, {
    s: 'Mac OS',
    r: /(MacPPC|MacIntel|Mac_PowerPC|Macintosh)/
  }, {
    s: 'QNX',
    r: /QNX/
  }, {
    s: 'UNIX',
    r: /UNIX/
  }, {
    s: 'OS/2',
    r: /OS\/2/
  }];

  for (var i = 0; i < osInfo.length; i += 1) {
    var val = osInfo[i];

    if (val.r.test(userAgent)) {
      osName = val.s;
      break;
    }
  }

  if (/Windows/.test(osName)) {
    var index = 1;
    osVersion = /Windows (.*)/.exec(osName)[index];
    osName = 'Windows';
  }

  var versionInfo = {
    'Mac OS X': /Mac OS X (10[._\d]+)/,
    Android: /Android ([._\d]+)/,
    iOS: /OS (\d+)_(\d+)_?(\d+)?/
  };

  if (versionInfo[osName]) {
    osVersion = '';
    var substring = versionInfo[osName].exec(userAgent);

    if (substring) {
      osVersion = substring[1].replace(/_/g, '.');
      osVersion = osVersion.substr(0, Math.min(osVersion.length, 5));
    }
  }

  return {
    osName: osName,
    osVersion: osVersion
  };
}
function getBrowserInfo(userAgent) {
  if (!userAgent) {
    return {
      browserName: NA,
      browserVersion: NA
    };
  }

  var browserName = '';
  var browserVersion = '';
  /*
  s: the browser name
  r: regex for searching name
  ofs: offset for Version
  ofsV: if userAgent has Version keyword, this is the offset we want
  */

  var browserInfo = [{
    s: 'Opera',
    r: 'Opera',
    ofs: 6,
    ofsV: 8
  }, {
    s: 'Opera',
    r: 'OPR',
    ofs: 4
  }, {
    s: 'Microsoft Edge',
    r: 'Edge',
    ofs: 5
  }, {
    s: 'Microsoft Internet Explorer',
    r: 'MSIE',
    ofs: 5
  }, {
    s: 'Chrome',
    r: 'Chrome',
    ofs: 7
  }, {
    s: 'Safari',
    r: 'Safari',
    ofs: 7,
    ofsV: 8
  }, {
    s: 'Firefox',
    r: 'Firefox',
    ofs: 8
  }, {
    s: 'Microsoft Internet Explorer',
    r: 'rv:',
    ofs: 3
  }, {
    s: 'Other',
    r: ''
  }];
  var separator = [';', ' ', ')'];

  for (var i = 0; i < browserInfo.length; i += 1) {
    var browser = browserInfo[i];
    var offset = void 0;
    offset = userAgent.indexOf(browser.r);

    if (offset !== -1) {
      browserName = browser.s;
      browserVersion = userAgent.substring(offset + browser.ofs);
      offset = userAgent.indexOf('Version');

      if (offset !== -1) {
        browserVersion = userAgent.substring(offset + browser.ofsV);
      }

      break;
    } // special handling for other browser


    if (browser.s === 'Other') {
      var nameOffset = userAgent.lastIndexOf(' ') + 1;
      var verOffset = userAgent.lastIndexOf('/');
      browserName = userAgent.substring(nameOffset, verOffset);
      browserVersion = userAgent.substring(verOffset + 1);

      if (browserName.toLowerCase() === browserName.toUpperCase()) {
        browserVersion = window.navigator.appName;
      }

      break;
    }
  }

  separator.forEach(function (s) {
    browserVersion = strip(browserVersion, s);
  });
  return {
    browserName: browserName,
    browserVersion: browserVersion
  };
}

function generateExperienceID() {
  function seed() {
    return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
  }

  return "".concat(seed()).concat(seed(), "-").concat(seed(), "-").concat(seed(), "-").concat(seed(), "-").concat(seed()).concat(seed()).concat(seed());
}

function sendEvent(factory, options) {
  var platform;
  var userAgent;

  if (window.navigator) {
    userAgent = window.navigator.userAgent;
    platform = window.navigator.platform;
  }

  var osInfo = getOsInfo(userAgent);
  var browserInfo = getBrowserInfo(userAgent);
  var event = {
    type: 'session_start',
    data: {
      device: platform || NA,
      os: osInfo.osName || NA,
      osVersion: osInfo.osVersion || NA,
      locale: window.$C.LOCALE || NA,
      browser: browserInfo.browserName || NA,
      browserVersion: browserInfo.browserVersion || NA,
      splunkVersion: window.$C.VERSION_LABEL || NA,
      guid: options.instanceGUID
    }
  };
  factory(event);
}

function SessionHandler(factory, options) {
  if (newSession) {
    sendEvent(factory, options);
    newSession = false;
  }
}

SessionHandler.init = function init(options) {
  var savedToken = getValueFromCookie(options.cookieSavedTokenKeyRegex);
  var token = getValueFromCookie(options.cookieCSRFRegex);
  var experienceID = getValueFromCookie(options.cookieExperienceIDRegex);

  if (savedToken !== token || !experienceID) {
    newSession = true;
    experienceID = generateExperienceID();
    setValueToCookie(options.savedTokenKey, token);
    setValueToCookie(options.experienceIDKey, experienceID);
  }

  var update = {
    experienceID: getValueFromCookie(options.cookieExperienceIDRegex)
  };
  options.updateOptions(update);
};
// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/Core.es











var Core_SWACore = /*#__PURE__*/function () {
  function SWACore(options) {
    classCallCheck_default()(this, SWACore);

    if (!SWACore.isLocalStorageAvailable()) {
      /* Stop SWA from running if there is no localStorage
       * (happens in Safari Private Browsing Session)
       * will try to fix this in the future.
       * */
      return;
    }

    this.handlers = {};
    this._options = {};
    this.updateOptions(SWA_constants);
    this._options.updateOptions = this.updateOptions.bind(this);
    this._options.log = this.log.bind(this);
    this.updateOptions(options);
    this.registerHandler('SessionHandler', SessionHandler);
    this.registerHandler('RecoveryHandler', RecoveryHandler);
    this.registerHandler('ApiHandler', ApiHandler);
    this.registerHandler('PageHandler', PageHandler);
    this._options.cache = this._options.cache || new Cache_Cache(this._options);
    this._options.dispatcher = this._options.dispatcher || new Dispatcher_Dispatcher(this._options);
    this._options.eventQueue = this._options.eventQueue || new EventQueue_EventQueue(this._options, this._options.dispatcher);
    this._options.factory = this._options.eventQueue.factory;
    this.loadHandlers();
  }

  createClass_default()(SWACore, [{
    key: "updateOptions",
    value: function updateOptions(options) {
      var _this = this;

      // Overrides/extends default options.
      // Only certain options are available to override.
      ['bundleDataFunction', 'eventRecovery', 'cache', 'cacheKey', 'deploymentID', 'dispatcher', 'eventParser', 'eventQueue', 'factory', 'maxQueueSize', 'mintUuid', 'log', 'logging', 'queueFailureMax', 'experienceIDKey', 'updateOptions', 'userID', 'cookieRegex', 'experienceID', 'savedTokenKey', 'url', 'version', 'visibility', 'instanceGUID', 'cookieExperienceIDRegex', 'cookieSavedTokenKeyRegex', 'cookieCSRFRegex'].forEach(function (key) {
        if (typeof options[key] !== 'undefined') {
          _this._options[key] = options[key];
        }
      });
      Object.keys(options.handlers || {}).forEach(function (key) {
        _this.registerHandler(key, options.handlers[key]);
      });
    }
  }, {
    key: "registerHandler",
    value: function registerHandler(name, handler) {
      this.handlers[name] = {
        handler: handler
      };

      if (handler.init) {
        handler.init(this._options);
      }
    }
  }, {
    key: "loadHandlers",
    value: function loadHandlers() {
      var _this2 = this;

      Object.keys(this.handlers).forEach(function (key) {
        var handler = _this2.handlers[key];

        if (!handler.loaded) {
          try {
            handler.handler(_this2._options.factory, _this2._options);
          } finally {
            handler.loaded = true;
          }
        }
      });
    }
  }, {
    key: "log",
    value: function log() {
      if (this._options.devMode || this._options.logging) {
        var _window$console;

        (_window$console = window.console).log.apply(_window$console, arguments);
      }
    }
  }, {
    key: "getOption",
    value: function getOption(key) {
      return this._options[key];
    }
  }], [{
    key: "isLocalStorageAvailable",
    value: function isLocalStorageAvailable() {
      try {
        localStorage.setItem('is', 'available');
      } catch (e) {
        return false;
      }

      return true;
    }
  }]);

  return SWACore;
}();


window.SWA = window.SWA || Core_SWACore;
// CONCATENATED MODULE: ./splunk_instrumentation/src/SWA/swa.es



/***/ }),

/***/ 111:
/***/ (function(module, exports, __webpack_require__) {

var isCallable = __webpack_require__(61);

module.exports = function (it) {
  return typeof it === 'object' ? it !== null : isCallable(it);
};


/***/ }),

/***/ 12:
/***/ (function(module, exports) {

function _classCallCheck(instance, Constructor) {
  if (!(instance instanceof Constructor)) {
    throw new TypeError("Cannot call a class as a function");
  }
}

module.exports = _classCallCheck, module.exports.__esModule = true, module.exports["default"] = module.exports;

/***/ }),

/***/ 13:
/***/ (function(module, exports) {

function _defineProperties(target, props) {
  for (var i = 0; i < props.length; i++) {
    var descriptor = props[i];
    descriptor.enumerable = descriptor.enumerable || false;
    descriptor.configurable = true;
    if ("value" in descriptor) descriptor.writable = true;
    Object.defineProperty(target, descriptor.key, descriptor);
  }
}

function _createClass(Constructor, protoProps, staticProps) {
  if (protoProps) _defineProperties(Constructor.prototype, protoProps);
  if (staticProps) _defineProperties(Constructor, staticProps);
  Object.defineProperty(Constructor, "prototype", {
    writable: false
  });
  return Constructor;
}

module.exports = _createClass, module.exports.__esModule = true, module.exports["default"] = module.exports;

/***/ }),

/***/ 202:
/***/ (function(module, exports, __webpack_require__) {

// toObject with fallback for non-array-like ES3 strings
var IndexedObject = __webpack_require__(523);
var requireObjectCoercible = __webpack_require__(525);

module.exports = function (it) {
  return IndexedObject(requireObjectCoercible(it));
};


/***/ }),

/***/ 203:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);
var isCallable = __webpack_require__(61);

var aFunction = function (argument) {
  return isCallable(argument) ? argument : undefined;
};

module.exports = function (namespace, method) {
  return arguments.length < 2 ? aFunction(global[namespace]) : global[namespace] && global[namespace][method];
};


/***/ }),

/***/ 204:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);
var setGlobal = __webpack_require__(205);

var SHARED = '__core-js_shared__';
var store = global[SHARED] || setGlobal(SHARED, {});

module.exports = store;


/***/ }),

/***/ 205:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);

module.exports = function (key, value) {
  try {
    // eslint-disable-next-line es/no-object-defineproperty -- safe
    Object.defineProperty(global, key, { value: value, configurable: true, writable: true });
  } catch (error) {
    global[key] = value;
  } return value;
};


/***/ }),

/***/ 206:
/***/ (function(module, exports, __webpack_require__) {

var DESCRIPTORS = __webpack_require__(85);
var definePropertyModule = __webpack_require__(534);
var createPropertyDescriptor = __webpack_require__(522);

module.exports = DESCRIPTORS ? function (object, key, value) {
  return definePropertyModule.f(object, key, createPropertyDescriptor(1, value));
} : function (object, key, value) {
  object[key] = value;
  return object;
};


/***/ }),

/***/ 51:
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(global) {var check = function (it) {
  return it && it.Math == Math && it;
};

// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
module.exports =
  // eslint-disable-next-line es/no-global-this -- safe
  check(typeof globalThis == 'object' && globalThis) ||
  check(typeof window == 'object' && window) ||
  // eslint-disable-next-line no-restricted-globals -- safe
  check(typeof self == 'object' && self) ||
  check(typeof global == 'object' && global) ||
  // eslint-disable-next-line no-new-func -- fallback
  (function () { return this; })() || Function('return this')();

/* WEBPACK VAR INJECTION */}.call(this, __webpack_require__(53)))

/***/ }),

/***/ 519:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);
var getOwnPropertyDescriptor = __webpack_require__(520).f;
var createNonEnumerableProperty = __webpack_require__(206);
var redefine = __webpack_require__(1079);
var setGlobal = __webpack_require__(205);
var copyConstructorProperties = __webpack_require__(1084);
var isForced = __webpack_require__(1090);

/*
  options.target      - name of the target object
  options.global      - target is the global object
  options.stat        - export as static methods of target
  options.proto       - export as prototype methods of target
  options.real        - real prototype method for the `pure` version
  options.forced      - export even if the native feature is available
  options.bind        - bind methods to the target, required for the `pure` version
  options.wrap        - wrap constructors to preventing global pollution, required for the `pure` version
  options.unsafe      - use the simple assignment of property instead of delete + defineProperty
  options.sham        - add a flag to not completely full polyfills
  options.enumerable  - export as enumerable property
  options.noTargetGet - prevent calling a getter on target
  options.name        - the .name of the function if it does not match the key
*/
module.exports = function (options, source) {
  var TARGET = options.target;
  var GLOBAL = options.global;
  var STATIC = options.stat;
  var FORCED, target, key, targetProperty, sourceProperty, descriptor;
  if (GLOBAL) {
    target = global;
  } else if (STATIC) {
    target = global[TARGET] || setGlobal(TARGET, {});
  } else {
    target = (global[TARGET] || {}).prototype;
  }
  if (target) for (key in source) {
    sourceProperty = source[key];
    if (options.noTargetGet) {
      descriptor = getOwnPropertyDescriptor(target, key);
      targetProperty = descriptor && descriptor.value;
    } else targetProperty = target[key];
    FORCED = isForced(GLOBAL ? key : TARGET + (STATIC ? '.' : '#') + key, options.forced);
    // contained in target
    if (!FORCED && targetProperty !== undefined) {
      if (typeof sourceProperty === typeof targetProperty) continue;
      copyConstructorProperties(sourceProperty, targetProperty);
    }
    // add a flag to not completely full polyfills
    if (options.sham || (targetProperty && targetProperty.sham)) {
      createNonEnumerableProperty(sourceProperty, 'sham', true);
    }
    // extend global
    redefine(target, key, sourceProperty, options);
  }
};


/***/ }),

/***/ 520:
/***/ (function(module, exports, __webpack_require__) {

var DESCRIPTORS = __webpack_require__(85);
var propertyIsEnumerableModule = __webpack_require__(521);
var createPropertyDescriptor = __webpack_require__(522);
var toIndexedObject = __webpack_require__(202);
var toPropertyKey = __webpack_require__(526);
var has = __webpack_require__(78);
var IE8_DOM_DEFINE = __webpack_require__(533);

// eslint-disable-next-line es/no-object-getownpropertydescriptor -- safe
var $getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;

// `Object.getOwnPropertyDescriptor` method
// https://tc39.es/ecma262/#sec-object.getownpropertydescriptor
exports.f = DESCRIPTORS ? $getOwnPropertyDescriptor : function getOwnPropertyDescriptor(O, P) {
  O = toIndexedObject(O);
  P = toPropertyKey(P);
  if (IE8_DOM_DEFINE) try {
    return $getOwnPropertyDescriptor(O, P);
  } catch (error) { /* empty */ }
  if (has(O, P)) return createPropertyDescriptor(!propertyIsEnumerableModule.f.call(O, P), O[P]);
};


/***/ }),

/***/ 521:
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var $propertyIsEnumerable = {}.propertyIsEnumerable;
// eslint-disable-next-line es/no-object-getownpropertydescriptor -- safe
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;

// Nashorn ~ JDK8 bug
var NASHORN_BUG = getOwnPropertyDescriptor && !$propertyIsEnumerable.call({ 1: 2 }, 1);

// `Object.prototype.propertyIsEnumerable` method implementation
// https://tc39.es/ecma262/#sec-object.prototype.propertyisenumerable
exports.f = NASHORN_BUG ? function propertyIsEnumerable(V) {
  var descriptor = getOwnPropertyDescriptor(this, V);
  return !!descriptor && descriptor.enumerable;
} : $propertyIsEnumerable;


/***/ }),

/***/ 522:
/***/ (function(module, exports) {

module.exports = function (bitmap, value) {
  return {
    enumerable: !(bitmap & 1),
    configurable: !(bitmap & 2),
    writable: !(bitmap & 4),
    value: value
  };
};


/***/ }),

/***/ 523:
/***/ (function(module, exports, __webpack_require__) {

var fails = __webpack_require__(86);
var classof = __webpack_require__(524);

var split = ''.split;

// fallback for non-array-like ES3 and non-enumerable old V8 strings
module.exports = fails(function () {
  // throws an error in rhino, see https://github.com/mozilla/rhino/issues/346
  // eslint-disable-next-line no-prototype-builtins -- safe
  return !Object('z').propertyIsEnumerable(0);
}) ? function (it) {
  return classof(it) == 'String' ? split.call(it, '') : Object(it);
} : Object;


/***/ }),

/***/ 524:
/***/ (function(module, exports) {

var toString = {}.toString;

module.exports = function (it) {
  return toString.call(it).slice(8, -1);
};


/***/ }),

/***/ 525:
/***/ (function(module, exports) {

// `RequireObjectCoercible` abstract operation
// https://tc39.es/ecma262/#sec-requireobjectcoercible
module.exports = function (it) {
  if (it == undefined) throw TypeError("Can't call method on " + it);
  return it;
};


/***/ }),

/***/ 526:
/***/ (function(module, exports, __webpack_require__) {

var toPrimitive = __webpack_require__(1069);
var isSymbol = __webpack_require__(527);

// `ToPropertyKey` abstract operation
// https://tc39.es/ecma262/#sec-topropertykey
module.exports = function (argument) {
  var key = toPrimitive(argument, 'string');
  return isSymbol(key) ? key : String(key);
};


/***/ }),

/***/ 527:
/***/ (function(module, exports, __webpack_require__) {

var isCallable = __webpack_require__(61);
var getBuiltIn = __webpack_require__(203);
var USE_SYMBOL_AS_UID = __webpack_require__(528);

module.exports = USE_SYMBOL_AS_UID ? function (it) {
  return typeof it == 'symbol';
} : function (it) {
  var $Symbol = getBuiltIn('Symbol');
  return isCallable($Symbol) && Object(it) instanceof $Symbol;
};


/***/ }),

/***/ 528:
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable es/no-symbol -- required for testing */
var NATIVE_SYMBOL = __webpack_require__(529);

module.exports = NATIVE_SYMBOL
  && !Symbol.sham
  && typeof Symbol.iterator == 'symbol';


/***/ }),

/***/ 529:
/***/ (function(module, exports, __webpack_require__) {

/* eslint-disable es/no-symbol -- required for testing */
var V8_VERSION = __webpack_require__(1070);
var fails = __webpack_require__(86);

// eslint-disable-next-line es/no-object-getownpropertysymbols -- required for testing
module.exports = !!Object.getOwnPropertySymbols && !fails(function () {
  var symbol = Symbol();
  // Chrome 38 Symbol has incorrect toString conversion
  // `get-own-property-symbols` polyfill symbols converted to object are not Symbol instances
  return !String(symbol) || !(Object(symbol) instanceof Symbol) ||
    // Chrome 38-40 symbols are not inherited from DOM collections prototypes to instances
    !Symbol.sham && V8_VERSION && V8_VERSION < 41;
});


/***/ }),

/***/ 53:
/***/ (function(module, exports) {

var g;

// This works in non-strict mode
g = (function() {
	return this;
})();

try {
	// This works if eval is allowed (see CSP)
	g = g || new Function("return this")();
} catch (e) {
	// This works if the window reference is available
	if (typeof window === "object") g = window;
}

// g can still be undefined, but nothing to do about it...
// We return undefined, instead of nothing here, so it's
// easier to handle this case. if(!global) { ...}

module.exports = g;


/***/ }),

/***/ 530:
/***/ (function(module, exports, __webpack_require__) {

var IS_PURE = __webpack_require__(1077);
var store = __webpack_require__(204);

(module.exports = function (key, value) {
  return store[key] || (store[key] = value !== undefined ? value : {});
})('versions', []).push({
  version: '3.18.1',
  mode: IS_PURE ? 'pure' : 'global',
  copyright: '© 2021 Denis Pushkarev (zloirock.ru)'
});


/***/ }),

/***/ 531:
/***/ (function(module, exports, __webpack_require__) {

var requireObjectCoercible = __webpack_require__(525);

// `ToObject` abstract operation
// https://tc39.es/ecma262/#sec-toobject
module.exports = function (argument) {
  return Object(requireObjectCoercible(argument));
};


/***/ }),

/***/ 532:
/***/ (function(module, exports) {

var id = 0;
var postfix = Math.random();

module.exports = function (key) {
  return 'Symbol(' + String(key === undefined ? '' : key) + ')_' + (++id + postfix).toString(36);
};


/***/ }),

/***/ 533:
/***/ (function(module, exports, __webpack_require__) {

var DESCRIPTORS = __webpack_require__(85);
var fails = __webpack_require__(86);
var createElement = __webpack_require__(1078);

// Thank's IE8 for his funny defineProperty
module.exports = !DESCRIPTORS && !fails(function () {
  // eslint-disable-next-line es/no-object-defineproperty -- requied for testing
  return Object.defineProperty(createElement('div'), 'a', {
    get: function () { return 7; }
  }).a != 7;
});


/***/ }),

/***/ 534:
/***/ (function(module, exports, __webpack_require__) {

var DESCRIPTORS = __webpack_require__(85);
var IE8_DOM_DEFINE = __webpack_require__(533);
var anObject = __webpack_require__(535);
var toPropertyKey = __webpack_require__(526);

// eslint-disable-next-line es/no-object-defineproperty -- safe
var $defineProperty = Object.defineProperty;

// `Object.defineProperty` method
// https://tc39.es/ecma262/#sec-object.defineproperty
exports.f = DESCRIPTORS ? $defineProperty : function defineProperty(O, P, Attributes) {
  anObject(O);
  P = toPropertyKey(P);
  anObject(Attributes);
  if (IE8_DOM_DEFINE) try {
    return $defineProperty(O, P, Attributes);
  } catch (error) { /* empty */ }
  if ('get' in Attributes || 'set' in Attributes) throw TypeError('Accessors not supported');
  if ('value' in Attributes) O[P] = Attributes.value;
  return O;
};


/***/ }),

/***/ 535:
/***/ (function(module, exports, __webpack_require__) {

var isObject = __webpack_require__(111);

// `Assert: Type(argument) is Object`
module.exports = function (argument) {
  if (isObject(argument)) return argument;
  throw TypeError(String(argument) + ' is not an object');
};


/***/ }),

/***/ 536:
/***/ (function(module, exports, __webpack_require__) {

var isCallable = __webpack_require__(61);
var store = __webpack_require__(204);

var functionToString = Function.toString;

// this helper broken in `core-js@3.4.1-3.4.4`, so we can't use `shared` helper
if (!isCallable(store.inspectSource)) {
  store.inspectSource = function (it) {
    return functionToString.call(it);
  };
}

module.exports = store.inspectSource;


/***/ }),

/***/ 537:
/***/ (function(module, exports) {

module.exports = {};


/***/ }),

/***/ 538:
/***/ (function(module, exports, __webpack_require__) {

var has = __webpack_require__(78);
var toIndexedObject = __webpack_require__(202);
var indexOf = __webpack_require__(1087).indexOf;
var hiddenKeys = __webpack_require__(537);

module.exports = function (object, names) {
  var O = toIndexedObject(object);
  var i = 0;
  var result = [];
  var key;
  for (key in O) !has(hiddenKeys, key) && has(O, key) && result.push(key);
  // Don't enum bug & hidden keys
  while (names.length > i) if (has(O, key = names[i++])) {
    ~indexOf(result, key) || result.push(key);
  }
  return result;
};


/***/ }),

/***/ 539:
/***/ (function(module, exports) {

var ceil = Math.ceil;
var floor = Math.floor;

// `ToInteger` abstract operation
// https://tc39.es/ecma262/#sec-tointeger
module.exports = function (argument) {
  return isNaN(argument = +argument) ? 0 : (argument > 0 ? floor : ceil)(argument);
};


/***/ }),

/***/ 540:
/***/ (function(module, exports) {

// IE8- don't enum bug keys
module.exports = [
  'constructor',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toLocaleString',
  'toString',
  'valueOf'
];


/***/ }),

/***/ 541:
/***/ (function(module, exports) {

// eslint-disable-next-line es/no-object-getownpropertysymbols -- safe
exports.f = Object.getOwnPropertySymbols;


/***/ }),

/***/ 542:
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(51);

module.exports = global;


/***/ }),

/***/ 568:
/***/ (function(module, exports, __webpack_require__) {

var parent = __webpack_require__(1066);

module.exports = parent;


/***/ }),

/***/ 569:
/***/ (function(module, exports, __webpack_require__) {

var parent = __webpack_require__(1093);

module.exports = parent;


/***/ }),

/***/ 61:
/***/ (function(module, exports) {

// `IsCallable` abstract operation
// https://tc39.es/ecma262/#sec-iscallable
module.exports = function (argument) {
  return typeof argument === 'function';
};


/***/ }),

/***/ 78:
/***/ (function(module, exports, __webpack_require__) {

var toObject = __webpack_require__(531);

var hasOwnProperty = {}.hasOwnProperty;

module.exports = Object.hasOwn || function hasOwn(it, key) {
  return hasOwnProperty.call(toObject(it), key);
};


/***/ }),

/***/ 85:
/***/ (function(module, exports, __webpack_require__) {

var fails = __webpack_require__(86);

// Detect IE8's incomplete defineProperty implementation
module.exports = !fails(function () {
  // eslint-disable-next-line es/no-object-defineproperty -- required for testing
  return Object.defineProperty({}, 1, { get: function () { return 7; } })[1] != 7;
});


/***/ }),

/***/ 86:
/***/ (function(module, exports) {

module.exports = function (exec) {
  try {
    return !!exec();
  } catch (error) {
    return true;
  }
};


/***/ }),

/***/ 9:
/***/ (function(module, exports) {

function _defineProperty(obj, key, value) {
  if (key in obj) {
    Object.defineProperty(obj, key, {
      value: value,
      enumerable: true,
      configurable: true,
      writable: true
    });
  } else {
    obj[key] = value;
  }

  return obj;
}

module.exports = _defineProperty, module.exports.__esModule = true, module.exports["default"] = module.exports;

/***/ })

/******/ });