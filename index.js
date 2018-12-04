const IV_LENGTH = 16;

export async function encrypt(inputBlob) {
    const key = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const inputArray = (await blobToArrayBuffer(inputBlob)).target.result;
    const cypher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, inputArray);
    const payload = new Uint8Array(cypher.byteLength + iv.byteLength);
    payload.set(new Uint8Array(cypher));
    payload.set(iv, cypher.byteLength);
    const exportedKey = await crypto.subtle.exportKey('jwk', key);

    return {
        key: exportedKey,
        payload: new Blob([payload]),
    };
}

export async function decrypt(dataBlob, jwk) {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const dataArray = (await blobToArrayBuffer(dataBlob)).target.result;
    const cypher = dataArray.slice(0, dataArray.byteLength - IV_LENGTH);
    const iv = dataArray.slice(cypher.byteLength, dataArray.byteLength);
    const decyphered = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, cypher);
    const decypheredAsBlob = new Blob([new Uint8Array(decyphered)]);
    return decypheredAsBlob;
}

function blobToArrayBuffer(blob) {
    var fileReader = new FileReader();

    return new Promise(function (resolve, reject) {
        fileReader.onload = resolve;
        fileReader.onerror = reject;

        fileReader.readAsArrayBuffer(blob);
    });
};
