var HTTP_DOMAIN = "http.jinzihao.me";
var PUBLIC_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mQENBFqX5gIBCADIbiIhUahlwjsCT/CJ5vxj4/PsAKi/ar8Nxp5BtJFBmiXAfv1n
myockCmUu5DX9Il5oBWz1uVqVTFcdkTPk7XUwG6v0YkNb+XtJ3Vszk6Y2yI9S1++
H37RZzhzRC+e6DMbPt+ZUd/MOGjhC957K6QV459WSIMThVwk5yCn9wYDWJ3UdvFO
98LgmKBSOwQbsL5kX1udhLnm8S2PbZBJ04EUI8pLBonV8u00gdi51xZrOjmjF/4z
J9u58eQHX2OXohzIdCYce5D+VXIofvl1sx0P2M6JykmA4U1NQf8KpuIAm7avcKd1
3xwqPnhfTuqDtfBkMIrQsbOi65G60KtsNuwHABEBAAG0G2ppbnppaGFvIDw5MDM3
MDMyODdAcXEuY29tPokBOAQTAQIAIgUCWpfmAgIbAwYLCQgHAwIGFQgCCQoLBBYC
AwECHgECF4AACgkQo7GhuiqANqzYSAf/YSraGq4g56HGDBr+5sbREwgz2JrmZeGc
+ouJ8bx5Ffa+8IONr/Ik2baADkPJ42WGBzDUAzDtk9YatgUQSbLmJJZGMPMmw2Rd
PIIBrTAHdJ8HxOSR5ptOiJxxJ1Q3AR0hsNZ3AuzB2udvdhP8QaEvfa+TKRWLFkCy
bC30MfNRb6TS/joObfx2OVFii2kHucQZrtMaHfnTdQZQbs/rSu5vhiv09v+sV5nX
XdHvYHMdgMYlYUsnV7fuUpk2n7kp/Wjvx3pf+vNi7/dvSM6gai0Odw2HFoMJ1B1T
KfHWxFdux2CFuJOUxHBzznajoYMZyBzXDRcSorVOFQBCytA9kZnF/LkBDQRal+YC
AQgApt2Tr49uWM/0c9C51vlY8H0CQp9qT7J/b+qBCKMbBWvmPQAYFcK36PLQMIyA
/AGtmKqB1uMAcB5hFGNEsTNS/DvlLRJ3SpXfCuAM6Ev7KmNUkvWHRxK3jaJOWZvc
ERAdUTbhTL6UZAEwmW6b0lfk6Z8x3HXzUNLv7X0cB8b/S+QjKZKAT/qKVtyFw2uG
a9TPKQkVZQLO5un7DsixTpg7XopCuf7xUd+X/g2w2Q0gYU69bnr5yvcz9xxA8aNH
eSGQxZCNt4n8B6uRTbhFfCSzenlcuSU/Nx7ktemG5ZFLyGqSNVZQdvEpuz/pEsba
ZzdSFcZHWhFW+ZQjVqtd3UyHoQARAQABiQEfBBgBAgAJBQJal+YCAhsMAAoJEKOx
oboqgDasSgkH/0vxK+gqKR5qq7jKpM9Odc6b8/KBrPP/3REbw01eRpwAGuCNZA7j
PbGU6ynrbXu0n2PPstSX4AbAYxQlXaHFW2N7EUiznW8H8fuDv1bpd64DWBN4YBU2
ltPYza1NMIq4d/3sUdipYNca5hIr3iN+148YD4AbDTuM6/TfwZGtUUGS4uhjGuUs
GUiK31sY1jBmyC1NImNO9BfblKPDI22DLW6Tn2FF665RSb6A6RlcKBDhGSL4PUA5
4wdcOiMc/wUkQSS0IZmumEoYFTxsjlXK0EwURRUtl81FRNa9h41s3Dq8M49UfWcj
xckP+IpZQEzgPR8eJmaBcBua8yoWgi3/hpc=
=313A
-----END PGP PUBLIC KEY BLOCK-----`;

function isUrlInsideDomain(url, domain) {
    if (url.slice(0, 8).toLowerCase() === "https://" ||
        url.slice(0, 7).toLowerCase() === "http://" ||
        url.slice(0, 2) === "//") {
        if (url.split("/")[2].toLowerCase() === domain) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else {
        return 2;
    }
}

hookAjax = function (funs) {
    window._ahrealxhr = window._ahrealxhr || XMLHttpRequest
    XMLHttpRequest = function () {
        this.xhr = new window._ahrealxhr;
        this.xhr.originalResponseType = undefined;
        this.xhr.url = undefined;
        for (var attr in this.xhr) {
            var type = "";
            try {
                type = typeof this.xhr[attr]
            } catch (e) {}
            if (type === "function") {
                this[attr] = hookfun(attr);
            } else {
                Object.defineProperty(this, attr, {
                    get: getFactory(attr),
                    set: setFactory(attr)
                })
            }
        }
    }

    function getFactory(attr) {
        return function () {
            return this.hasOwnProperty(attr + "_")?this[attr + "_"]:this.xhr[attr];
        }
    }

    function setFactory(attr) {
        return function (f) {
            var xhr = this.xhr;
            var that = this;
            if (attr.indexOf("on") != 0) {
                this[attr + "_"] = f;
                return;
            }
            if (funs[attr]) {
                xhr[attr] = function () {
                    xhr.then = function() {
                        return f.apply(xhr, arguments)
                    };
                    funs[attr](that);
                }
            } else {
                xhr[attr] = f;
            }
        }
    }

    function hookfun(fun) {
        return function () {
            var args = [].slice.call(arguments)
            if (funs[fun] && funs[fun].call(this, args, this.xhr)) {
                return;
            }
            return this.xhr[fun].apply(this.xhr, args);
        }
    }
    return window._ahrealxhr;
}
unHookAjax = function () {
    if (window._ahrealxhr)  XMLHttpRequest = window._ahrealxhr;
    window._ahrealxhr = undefined;
}

var ajax_load_handler = function(xhr) {
    if (xhr.responseType === "blob" && (xhr.originalResponseType === "text" || xhr.originalResponseType === "") && xhr.response) {
        verifySignature(xhr.response, xhr.url, PUBLIC_KEY, function(data) {
            xhr.responseType = xhr.originalResponseType;
            xhr.responseText = new TextDecoder("utf-8").decode(data);
            xhr.xhr.then();
        },
        function() {});
    }
}

hookAjax({
    open : function(arg, xhr) {
        if (arg[1].indexOf("?") !== -1) {
            arg[1] += "&cryptoproxyredirected=1";
        }
        else {
            arg[1] += "?cryptoproxyredirected=1";
        }
        xhr.originalResponseType = xhr.responseType;
        xhr.url = arg[1];
        xhr.responseType = "blob";
    },

    onreadystatechange : ajax_load_handler,
    onload : ajax_load_handler
})

$.ajaxTransport("+binary", function(options, originalOptions, jqXHR){
    // check for conditions and support for blob / arraybuffer response type
    if (window.FormData && ((options.dataType && (options.dataType == 'binary')) || (options.data && ((window.ArrayBuffer && options.data instanceof ArrayBuffer) || (window.Blob && options.data instanceof Blob)))))
    {
        return {
            // create new XMLHttpRequest
            send: function(headers, callback){
                // setup all variables
                var xhr = new window._ahrealxhr(),
                    url = options.url,
                    type = options.type,
                    async = options.async || true,
                    // blob or arraybuffer. Default is blob
                    dataType = options.responseType || "blob",
                    data = options.data || null,
                    username = options.username || null,
                    password = options.password || null;

                xhr.addEventListener('load', function(){
                    var data = {};
                    data[options.dataType] = xhr.response;
                    // make callback and send data
                    callback(xhr.status, xhr.statusText, data, xhr.getAllResponseHeaders());
                });

                xhr.open(type, url, async, username, password);

                // setup custom headers
                for (var i in headers) {
                    xhr.setRequestHeader(i, headers[i] );
                }

                xhr.responseType = dataType;
                xhr.send(data);
            },
            abort: function(){
                jqXHR.abort();
            }
        };
    }
});

function trim(s, c) {
    if (c === "]") c = "\\]";
    if (c === "\\") c = "\\\\";
    return s.replace(new RegExp(
        "^[" + c + "]+|[" + c + "]+$", "g"
    ), "");
}

function htmlDecode(input) {
    var doc = new DOMParser().parseFromString(input, "text/html");
    return doc.documentElement.textContent;
}

function saveData(data, filename) {
    var a = document.createElement('a');
    var url = window.URL.createObjectURL(data);
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

function decrypt(url, password, success, fail) {
    // Load a GPG encrypted file from <url>,
    // decrypt the file with <password>,
    // pass the file as a Uint8Array to <callback> function.
    $.ajax({
        url: htmlDecode(url),
        cache: true,
        type: "GET",
        dataType: "binary",
        processData: false,
        success: function(data) {
            var openpgp = window.openpgp;
            openpgp.initWorker({ path:'/js/openpgp.worker.js' });
            openpgp.config.aead_protect = true;

            var fr = new FileReader();
            fr.onload = function() {
                var u8 = new Uint8Array(this.result);

                options = {
                    message: openpgp.message.read(u8), // parse encrypted bytes
                    password: password,                 // decrypt with password
                    format: 'binary'                          // output as Uint8Array
                };
                openpgp.decrypt(options).then(function(plaintext) {
                    success(plaintext.data);
                });
            };
            fr.readAsArrayBuffer(data);
        }
    });
}

function verifySignature(data, url, password, success, fail) {
    var openpgp = window.openpgp;
    openpgp.initWorker({ path:'/js/openpgp.worker.js' });
    openpgp.config.aead_protect = true;

    var fr = new FileReader();
    fr.onload = function() {
        if (this.result.byteLength < 8) {
            if (isUrlInsideDomain(HTTP_DOMAIN) !== 1) {
                success(this.result);
            }
            else {
                console.log("Failed to verify the digital signature of " + url + ".");
                fail();
            }
        }
        else {
            var magic_number = new Uint8Array(this.result, 0, 8);
            if (magic_number[0] === 251 &&
                magic_number[1] === 241 &&
                magic_number[2] === 239 &&
                magic_number[3] === 233 &&
                magic_number[4] === 229 &&
                magic_number[5] === 227 &&
                magic_number[6] === 223 &&
                magic_number[7] === 211) {
                var signature_length_uint8arr = new Uint8Array(this.result, 8, 4);
                var signature_length = signature_length_uint8arr[0] + signature_length_uint8arr[1] * 256
                    + signature_length_uint8arr[2] * 256 * 256 + signature_length_uint8arr[3] * 256 * 256 * 256;
                var signature = new Uint8Array(this.result, 12, signature_length);
                var content = new Uint8Array(this.result, 12 + signature_length);

                options = {
                    message: openpgp.message.fromBinary(content), // parse armored message
                    signature: openpgp.signature.read(signature), // parse detached signature
                    publicKeys: openpgp.key.readArmored(password).keys   // for verification
                };

                openpgp.verify(options).then(function(verified) {
                    if (verified.signatures[0].valid) {
                        success(verified.data);
                    }
                    else {
                        console.log("Failed to verify the digital signature of " + url + ".");
                        fail();
                    }
                });
            }
            else if (isUrlInsideDomain(HTTP_DOMAIN) !== 1) {
                success(this.result);
            }
            else {
                console.log("Failed to verify the digital signature of " + url + ".");
                fail();
            }
        }
    };
    fr.readAsArrayBuffer(data);
}

function verify(url, password, success, fail) {
    $.ajax({
        url: htmlDecode(url),
        cache: true,
        type: "GET",
        dataType: "binary",
        processData: false,
        success: function(data) {verifySignature(data, url, password, success, fail)}
    });
}

function process_script(data, status, sequence) {
    var temp_arr = [];
    temp_arr['status'] = status;
    temp_arr['script'] = data;
    crypto_proxy_scripts[sequence] = temp_arr;
    execute_script_queue();
}

function execute_script_queue() {
    var i, j;
    for (i = 0; i < crypto_proxy_scripts.length; ++i) {
        if (typeof crypto_proxy_scripts[i] === 'undefined') {
            break;
        }
    }
    for (j = 0; j < i; ++j) {
        if (crypto_proxy_scripts[j]['status'] === 0) {
            crypto_proxy_scripts[j]['status'] = -1;
            try {
                $.globalEval(crypto_proxy_scripts[j]['script']);
            }
            catch (err) {
                console.log(err);
            }
        }
        else if (crypto_proxy_scripts[j]['status'] === 1) {
            crypto_proxy_scripts[j]['status'] = -1;
            try {
                $.globalEval(crypto_proxy_scripts[j]["script"].toString().slice(13, -1));
            }
            catch (err) {
                console.log(err);
            }
        }
    }
}

function loadScript(operation, url, password, sequence) {
    operation(url, password, sequence >= 0
        ? function(data) {
            process_script(new TextDecoder("utf-8").decode(data), 0, sequence);
        }
        : function(data) {});
}

function loadImage(operation, url, password, element) {
    operation(url, password, function(data) {
        var reader = new FileReader();
        reader.readAsDataURL(new Blob([data]));
        reader.onloadend = function() {
            $("#" + element).attr('src', reader.result);
        }
    });
}

function loadFile(operation, url, password, filename) {
    operation(url, password, function(data) {saveData(new Blob([data]), filename);});
}

function loadCSS(operation, url, password) {
    var attributes = "";
    for (var i = 3; i < arguments.length; i += 2) {
        attributes += " " + arguments[i] + "=\"" + arguments[i + 1] + "\""
    }
    operation(url, password, function (data) {$("head").append("<style" + attributes + ">" + new TextDecoder("utf-8").decode(data) + "</style>");})
}

function loadHTML(operation, url, password) {
    // Load a GPG encrypted HTML file from <url>,
    // decrypt the file with <password>,
    // display the HTML.
    operation(url, password, function (data) {$('body').html(data);})
}