(function (global, factory) {
  if (typeof define === "function" && define.amd) {
    define("FrontendFileCrypto", ["exports"], factory);
  } else if (typeof exports !== "undefined") {
    factory(exports);
  } else {
    var mod = {
      exports: {}
    };
    factory(mod.exports);
    global.FrontendFileCrypto = mod.exports;
  }
})(this, function (exports) {
  "use strict";

  Object.defineProperty(exports, "__esModule", {
    value: true
  });
  exports.encryptBlob = encryptBlob;
  exports.decryptBlob = decryptBlob;
  exports.encryptBase64 = encryptBase64;
  exports.decryptBase64 = decryptBase64;
  exports.encryptBlobToBase64 = encryptBlobToBase64;
  exports.decryptBase64ToBlob = decryptBase64ToBlob;

  function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) {
    try {
      var info = gen[key](arg);
      var value = info.value;
    } catch (error) {
      reject(error);
      return;
    }

    if (info.done) {
      resolve(value);
    } else {
      Promise.resolve(value).then(_next, _throw);
    }
  }

  function _asyncToGenerator(fn) {
    return function () {
      var self = this,
          args = arguments;
      return new Promise(function (resolve, reject) {
        var gen = fn.apply(self, args);

        function _next(value) {
          asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value);
        }

        function _throw(err) {
          asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err);
        }

        _next(undefined);
      });
    };
  }

  var IV_LENGTH = 16;

  function encryptBlob(_x) {
    return _encryptBlob.apply(this, arguments);
  }

  function _encryptBlob() {
    _encryptBlob = _asyncToGenerator(regeneratorRuntime.mark(function _callee(input) {
      return regeneratorRuntime.wrap(function _callee$(_context) {
        while (1) {
          switch (_context.prev = _context.next) {
            case 0:
              _context.next = 2;
              return encrypt(input, true, true);

            case 2:
              return _context.abrupt("return", _context.sent);

            case 3:
            case "end":
              return _context.stop();
          }
        }
      }, _callee);
    }));
    return _encryptBlob.apply(this, arguments);
  }

  function decryptBlob(_x2, _x3) {
    return _decryptBlob.apply(this, arguments);
  }

  function _decryptBlob() {
    _decryptBlob = _asyncToGenerator(regeneratorRuntime.mark(function _callee2(payload, jwk) {
      return regeneratorRuntime.wrap(function _callee2$(_context2) {
        while (1) {
          switch (_context2.prev = _context2.next) {
            case 0:
              _context2.next = 2;
              return decrypt(payload, jwk, true, true);

            case 2:
              return _context2.abrupt("return", _context2.sent);

            case 3:
            case "end":
              return _context2.stop();
          }
        }
      }, _callee2);
    }));
    return _decryptBlob.apply(this, arguments);
  }

  function encryptBase64(_x4) {
    return _encryptBase.apply(this, arguments);
  }

  function _encryptBase() {
    _encryptBase = _asyncToGenerator(regeneratorRuntime.mark(function _callee3(input) {
      return regeneratorRuntime.wrap(function _callee3$(_context3) {
        while (1) {
          switch (_context3.prev = _context3.next) {
            case 0:
              _context3.next = 2;
              return encrypt(input, false, false);

            case 2:
              return _context3.abrupt("return", _context3.sent);

            case 3:
            case "end":
              return _context3.stop();
          }
        }
      }, _callee3);
    }));
    return _encryptBase.apply(this, arguments);
  }

  function decryptBase64(_x5, _x6) {
    return _decryptBase.apply(this, arguments);
  }

  function _decryptBase() {
    _decryptBase = _asyncToGenerator(regeneratorRuntime.mark(function _callee4(payload, jwk) {
      return regeneratorRuntime.wrap(function _callee4$(_context4) {
        while (1) {
          switch (_context4.prev = _context4.next) {
            case 0:
              _context4.next = 2;
              return decrypt(payload, jwk, false, false);

            case 2:
              return _context4.abrupt("return", _context4.sent);

            case 3:
            case "end":
              return _context4.stop();
          }
        }
      }, _callee4);
    }));
    return _decryptBase.apply(this, arguments);
  }

  function encryptBlobToBase64(_x7) {
    return _encryptBlobToBase.apply(this, arguments);
  }

  function _encryptBlobToBase() {
    _encryptBlobToBase = _asyncToGenerator(regeneratorRuntime.mark(function _callee5(input) {
      return regeneratorRuntime.wrap(function _callee5$(_context5) {
        while (1) {
          switch (_context5.prev = _context5.next) {
            case 0:
              _context5.next = 2;
              return encrypt(input, true, false);

            case 2:
              return _context5.abrupt("return", _context5.sent);

            case 3:
            case "end":
              return _context5.stop();
          }
        }
      }, _callee5);
    }));
    return _encryptBlobToBase.apply(this, arguments);
  }

  function decryptBase64ToBlob(_x8, _x9) {
    return _decryptBase64ToBlob.apply(this, arguments);
  }

  function _decryptBase64ToBlob() {
    _decryptBase64ToBlob = _asyncToGenerator(regeneratorRuntime.mark(function _callee6(payload, jwk) {
      return regeneratorRuntime.wrap(function _callee6$(_context6) {
        while (1) {
          switch (_context6.prev = _context6.next) {
            case 0:
              _context6.next = 2;
              return decrypt(payload, jwk, false, true);

            case 2:
              return _context6.abrupt("return", _context6.sent);

            case 3:
            case "end":
              return _context6.stop();
          }
        }
      }, _callee6);
    }));
    return _decryptBase64ToBlob.apply(this, arguments);
  }

  function encrypt(_x10, _x11, _x12) {
    return _encrypt.apply(this, arguments);
  }

  function _encrypt() {
    _encrypt = _asyncToGenerator(regeneratorRuntime.mark(function _callee7(input, inputIsBlob, outputIsBlob) {
      var key, iv, inputArray, cipher, payload, exportedKey;
      return regeneratorRuntime.wrap(function _callee7$(_context7) {
        while (1) {
          switch (_context7.prev = _context7.next) {
            case 0:
              _context7.next = 2;
              return window.crypto.subtle.generateKey({
                name: 'AES-GCM',
                length: 256
              }, true, ['encrypt', 'decrypt']);

            case 2:
              key = _context7.sent;
              iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));

              if (!inputIsBlob) {
                _context7.next = 10;
                break;
              }

              _context7.next = 7;
              return blobToArrayBuffer(input);

            case 7:
              _context7.t0 = _context7.sent.target.result;
              _context7.next = 11;
              break;

            case 10:
              _context7.t0 = base64ToArrayBuffer(input);

            case 11:
              inputArray = _context7.t0;
              _context7.next = 14;
              return crypto.subtle.encrypt({
                name: 'AES-GCM',
                iv: iv
              }, key, inputArray);

            case 14:
              cipher = _context7.sent;
              payload = new Uint8Array(cipher.byteLength + iv.byteLength);
              payload.set(new Uint8Array(cipher));
              payload.set(iv, cipher.byteLength);
              _context7.next = 20;
              return crypto.subtle.exportKey('jwk', key);

            case 20:
              exportedKey = _context7.sent;
              return _context7.abrupt("return", {
                key: exportedKey.k,
                payload: outputIsBlob ? arrayBufferToBlob(payload) : arrayBufferToBase64(payload)
              });

            case 22:
            case "end":
              return _context7.stop();
          }
        }
      }, _callee7);
    }));
    return _encrypt.apply(this, arguments);
  }

  function decrypt(_x13, _x14, _x15, _x16) {
    return _decrypt.apply(this, arguments);
  }

  function _decrypt() {
    _decrypt = _asyncToGenerator(regeneratorRuntime.mark(function _callee8(payload, keyToken, inputIsBlob, outputIsBlob) {
      var jwk, key, dataArray, cipher, iv, deciphered, decipheredAsBlob;
      return regeneratorRuntime.wrap(function _callee8$(_context8) {
        while (1) {
          switch (_context8.prev = _context8.next) {
            case 0:
              jwk = {
                alg: "A256GCM",
                ext: true,
                k: keyToken,
                key_ops: ["encrypt", "decrypt"],
                kty: "oct"
              };
              _context8.next = 3;
              return crypto.subtle.importKey('jwk', jwk, {
                name: 'AES-GCM',
                length: 256
              }, false, ['encrypt', 'decrypt']);

            case 3:
              key = _context8.sent;

              if (!inputIsBlob) {
                _context8.next = 10;
                break;
              }

              _context8.next = 7;
              return blobToArrayBuffer(payload);

            case 7:
              _context8.t0 = _context8.sent.target.result;
              _context8.next = 11;
              break;

            case 10:
              _context8.t0 = base64ToArrayBuffer(payload);

            case 11:
              dataArray = _context8.t0;
              cipher = dataArray.slice(0, dataArray.byteLength - IV_LENGTH);
              iv = dataArray.slice(cipher.byteLength, dataArray.byteLength);
              _context8.next = 16;
              return crypto.subtle.decrypt({
                name: 'AES-GCM',
                iv: iv
              }, key, cipher);

            case 16:
              deciphered = _context8.sent;
              decipheredAsBlob = outputIsBlob ? arrayBufferToBlob(deciphered) : arrayBufferToBase64(deciphered);
              return _context8.abrupt("return", decipheredAsBlob);

            case 19:
            case "end":
              return _context8.stop();
          }
        }
      }, _callee8);
    }));
    return _decrypt.apply(this, arguments);
  }

  function blobToArrayBuffer(blob) {
    var fileReader = new FileReader();
    return new Promise(function (resolve, reject) {
      fileReader.onload = resolve;
      fileReader.onerror = reject;
      fileReader.readAsArrayBuffer(blob);
    });
  }

  ;

  function arrayBufferToBlob(ab) {
    return new Blob([new Uint8Array(ab)]);
  }

  function base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);

    for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }

    return bytes.buffer;
  } // source: https://gist.github.com/jonleighton/958841


  function arrayBufferToBase64(arrayBuffer) {
    var base64 = '';
    var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var bytes = new Uint8Array(arrayBuffer);
    var byteLength = bytes.byteLength;
    var byteRemainder = byteLength % 3;
    var mainLength = byteLength - byteRemainder;
    var a, b, c, d;
    var chunk; // Main loop deals with bytes in chunks of 3

    for (var i = 0; i < mainLength; i = i + 3) {
      // Combine the three bytes into a single integer
      chunk = bytes[i] << 16 | bytes[i + 1] << 8 | bytes[i + 2]; // Use bitmasks to extract 6-bit segments from the triplet

      a = (chunk & 16515072) >> 18; // 16515072 = (2^6 - 1) << 18

      b = (chunk & 258048) >> 12; // 258048   = (2^6 - 1) << 12

      c = (chunk & 4032) >> 6; // 4032     = (2^6 - 1) << 6

      d = chunk & 63; // 63       = 2^6 - 1
      // Convert the raw binary segments to the appropriate ASCII encoding

      base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d];
    } // Deal with the remaining bytes and padding


    if (byteRemainder == 1) {
      chunk = bytes[mainLength];
      a = (chunk & 252) >> 2; // 252 = (2^6 - 1) << 2
      // Set the 4 least significant bits to zero

      b = (chunk & 3) << 4; // 3   = 2^2 - 1

      base64 += encodings[a] + encodings[b] + '==';
    } else if (byteRemainder == 2) {
      chunk = bytes[mainLength] << 8 | bytes[mainLength + 1];
      a = (chunk & 64512) >> 10; // 64512 = (2^6 - 1) << 10

      b = (chunk & 1008) >> 4; // 1008  = (2^6 - 1) << 4
      // Set the 2 least significant bits to zero

      c = (chunk & 15) << 2; // 15    = 2^4 - 1

      base64 += encodings[a] + encodings[b] + encodings[c] + '=';
    }

    return base64;
  }
});