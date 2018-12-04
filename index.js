const IV_LENGTH = 16;

export async function encrypt(inputBlob) {
    const key = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const inputArray = (await blobToArrayBuffer(inputBlob)).target.result;
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, inputArray);
    const payload = new Uint8Array(cipher.byteLength + iv.byteLength);
    payload.set(new Uint8Array(cipher));
    payload.set(iv, cipher.byteLength);
    const exportedKey = await crypto.subtle.exportKey('jwk', key);

    return {
        key: exportedKey,
        payload: new Blob([payload]),
    };
}

export async function decrypt(dataBlob, jwk) {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const dataArray = (await blobToArrayBuffer(dataBlob)).target.result;
    const cipher = dataArray.slice(0, dataArray.byteLength - IV_LENGTH);
    const iv = dataArray.slice(cipher.byteLength, dataArray.byteLength);
    const deciphered = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, cipher);
    const decipheredAsBlob = new Blob([new Uint8Array(deciphered)]);
    return decipheredAsBlob;
}

function blobToArrayBuffer(blob) {
    var fileReader = new FileReader();

    return new Promise(function (resolve, reject) {
        fileReader.onload = resolve;
        fileReader.onerror = reject;

        fileReader.readAsArrayBuffer(blob);
    });
};
