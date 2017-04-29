(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
/* jslint node: true, esnext: true */
/* global WebAssembly */
'use strict';

function utf8ArrayToString(array) {
    let data = '';
    for(let i = 0; i < array.length; ++i)
        data += '%'+array[i].toString(16);
    return decodeURIComponent(data);
}

function stringToUtf8Array(string) {
    const data = encodeURI(string), array = [];
    for(let i = 0; i < data.length; ++i) {
        if(data[i] == '%') {
            array.push(parseInt(data.substr(i+1, 2), 16));
            i += 2;
        } else
            array.push(data.charCodeAt(i));
    }
    return new Uint8Array(array);
}

module.exports = function(code) {
    for(const key in this.env)
        this.env[key] = this.env[key].bind(this);
    return WebAssembly.instantiate(code, { 'env': this.env }).then(function(result) {
        this.wasmModule = result.module;
        this.wasmInstance = result.instance;
        this.superPageByteAddress = this.wasmInstance.exports.memory.buffer.byteLength;
        this.wasmInstance.exports.memory.grow(1);
        return this;
    }.bind(this), function(error) {
        console.log(error);
    });
};

module.exports.prototype.createSymbol = function() {
    return this.call('_createSymbol');
};

module.exports.prototype.releaseSymbol = function(symbol) {
    this.call('_releaseSymbol', symbol);
    if(this.releasedSymbol)
        this.releasedSymbol(symbol);
};

module.exports.prototype.unlinkSymbol = function(symbol) {
    let pairs = this.queryArray(this.queryMask.MVV, symbol, 0, 0);
    for(let i = 0; i < pairs.length; i += 2)
        this.unlinkTriple(symbol, pairs[i], pairs[i+1]);
    pairs = this.queryArray(this.queryMask.VMV, 0, symbol, 0);
    for(let i = 0; i < pairs.length; i += 2)
        this.unlinkTriple(pairs[i], symbol, pairs[i+1]);
    pairs = this.queryArray(this.queryMask.VVM, 0, 0, symbol);
    for(let i = 0; i < pairs.length; i += 2)
        this.unlinkTriple(pairs[i], pairs[i+1], symbol);
    this.releaseSymbol(symbol);
};

module.exports.prototype.getBlobSize = function(symbol) {
    return this.call('getBlobSize', symbol);
};

module.exports.prototype.setBlobSize = function(symbol, size) {
    this.call('setBlobSize', symbol, size);
};

module.exports.prototype.decreaseBlobSize = function(symbol, offset, length) {
    return this.call('decreaseBlobSize', symbol, offset, length);
};

module.exports.prototype.increaseBlobSize = function(symbol, offset, length) {
    return this.call('increaseBlobSize', symbol, offset, length);
};

module.exports.prototype.readBlob = function(symbol, offset = 0, length = undefined) {
    let sliceOffset = 0;
    const bufferByteAddress = this.call('getStackPointer')-this.blobBufferSize,
          size = this.getBlobSize(symbol);
    if(!length)
        length = size-offset;
    if(length < 0 || offset < 0 || length+offset > size)
        return false;
    const data = new Uint8Array(Math.ceil(length/8));
    while(length > 0) {
        const sliceLength = Math.min(length, this.blobBufferSize*8);
        this.call('readBlob', symbol, offset+sliceOffset*8, sliceLength);
        const bufferSlice = this.getMemorySlice(bufferByteAddress, Math.ceil(sliceLength/8));
        data.set(bufferSlice, sliceOffset);
        length -= sliceLength;
        sliceOffset += Math.ceil(sliceLength/8);
    }
    return data;
};

module.exports.prototype.writeBlob = function(data, symbol, offset = 0, padding = 0) {
    let sliceOffset = 0;
    const bufferByteAddress = this.call('getStackPointer')-this.blobBufferSize,
          size = this.getBlobSize(symbol);
    if(padding < 0 || padding > 7)
        return false;
    let length = ((data === undefined) ? 0 : data.length*8)-padding;
    if(length < 0 || offset < 0 || length+offset > size)
        return false;
    while(length > 0) {
        const sliceLength = Math.min(length, this.blobBufferSize*8),
              bufferSlice = new Uint8Array(data.slice(sliceOffset, sliceOffset+Math.ceil(sliceLength/8)));
        this.setMemorySlice(bufferSlice, bufferByteAddress);
        this.call('writeBlob', symbol, offset+sliceOffset*8, sliceLength);
        length -= sliceLength;
        sliceOffset += Math.ceil(sliceLength/8);
    }
    return true;
};

module.exports.prototype.cryptBlob = function(symbol, key, nonce) {
    const blockSymbol = this.createSymbol(),
          block = new Uint8Array(64),
          view = DataView(block.buffer),
          str = "expand 32-byte k";
    for(let i = 0; i < str.length; ++i)
        block[i] = str.charCodeAt(i);
    block.set(key, 16);
    block.set(nonce, 48);
    this.setBlob(block, blockSymbol);
    this.call('chaCha20', symbol, blockSymbol);
    this.releaseSymbol(blockSymbol);
};

module.exports.prototype.getBlobType = function(symbol) {
    const result = this.queryArray(this.queryMask.MMV, symbol, this.symbolByName.BlobType, 0);
    return (result.length === 1) ? result[0] : 0;
};

module.exports.prototype.getBlob = function(symbol) {
    const type = this.getBlobType(symbol);
    const blob = this.readBlob(symbol),
          dataView = new DataView(blob.buffer);
    if(blob.length === 0)
        return;
    switch(type) {
        case this.symbolByName.Natural:
            return dataView.getUint32(0, true);
        case this.symbolByName.Integer:
            return dataView.getInt32(0, true);
        case this.symbolByName.Float:
            return dataView.getFloat32(0, true);
        case this.symbolByName.UTF8:
            return utf8ArrayToString(blob);
    }
    return blob;
};

module.exports.prototype.setBlob = function(data, symbol) {
    let type = 0, buffer = data;
    switch(typeof data) {
        case 'string':
            buffer = stringToUtf8Array(data);
            type = this.symbolByName.UTF8;
            break;
        case 'number':
            buffer = new Uint8Array(4);
            const view = new DataView(buffer.buffer);
            if(!Number.isInteger(data)) {
                view.setFloat32(0, data, true);
                type = this.symbolByName.Float;
            } else if(data < 0) {
                view.setInt32(0, data, true);
                type = this.symbolByName.Integer;
            } else {
                view.setUint32(0, data, true);
                type = this.symbolByName.Natural;
            }
            break;
    }
    const size = (buffer) ? buffer.length*8 : 0;
    this.setBlobSize(symbol, size);
    if(size > 0 && !this.writeBlob(buffer, symbol))
        return false;
    this.setSolitary(symbol, this.symbolByName.BlobType, type);
    return true;
};

module.exports.prototype.serializeBlob = function(symbol) {
    const blob = this.getBlob(symbol);
    switch(typeof blob) {
        case 'undefined':
            return '#'+symbol;
        case 'string':
            return '"'+blob+'"';
        case 'object':
            let string = '';
            for(let i = 0; i < blob.length; ++i) {
                const byte = blob[i];
                string += (byte&0xF).toString(16)+(byte>>4).toString(16);
            }
            return 'hex:'+string.toUpperCase();
        default:
            return ''+blob;
    }
};

module.exports.prototype.deserializeBlob = function(string) {
    if(string.length > 2 && string[0] == '"' && string[string.length-1] == '"')
        return string.substr(1, string.length-2);
    else if(string.length > 4 && string.substr(0, 4) == 'hex:') {
        const blob = new Uint8Array(Math.floor((string.length-4)/2));
        for(let i = 0; i < blob.length; ++i)
            blob[i] = parseInt(string[i*2+4], 16)|(parseInt(string[i*2+5], 16)<<4);
        return blob;
    } else if(!Number.isNaN(parseFloat(string)))
        return parseFloat(string);
    else if(!Number.isNaN(parseInt(string)))
        return parseInt(string);
};

module.exports.prototype.linkTriple = function(entity, attribute, value) {
    if(!this.call('link', entity, attribute, value))
        return false;
    if(this.linkedTriple)
        this.linkedTriple(entity, attribute, value);
    return true;
};

module.exports.prototype.unlinkTriple = function(entity, attribute, value) {
    if(!this.call('unlink', entity, attribute, value))
        return false;
    const referenceCount =
        this.queryCount(this.queryMask.MVV, entity, 0, 0)+
        this.queryCount(this.queryMask.VMV, 0, entity, 0)+
        this.queryCount(this.queryMask.VVM, 0, 0, entity);
    if(referenceCount == 0)
        this.releaseSymbol(entity);
    if(this.unlinkedTriple)
        this.unlinkedTriple(entity, attribute, value);
    return true;
};

module.exports.prototype.queryArray = function(mask, entity, attribute, value) {
    const resultSymbol = this.createSymbol();
    this.call('query', mask, entity, attribute, value, resultSymbol);
    const result = this.readSymbolBlob(resultSymbol);
    this.releaseSymbol(resultSymbol);
    return result;
};

module.exports.prototype.queryCount = function(mask, entity, attribute, value) {
    return this.call('query', mask, entity, attribute, value, 0);
};

module.exports.prototype.setSolitary = function(entity, attribute, newValue) {
    const result = this.queryArray(this.queryMask.MMV, entity, attribute, 0);
    let needsToBeLinked = true;
    for(const oldValue of result)
        if(oldValue == newValue)
            needsToBeLinked = false;
        else
            this.unlinkTriple(entity, attribute, oldValue);
    if(needsToBeLinked)
        this.linkTriple(entity, attribute, newValue);
};

module.exports.prototype.encodeOntologyBinary = function() {
    this.call('encodeOntologyBinary');
    const data = this.getBlob(this.symbolByName.BinaryOntologyCodec);
    this.setBlobSize(this.symbolByName.BinaryOntologyCodec, 0);
    return data;
};

module.exports.prototype.decodeOntologyBinary = function(data) {
    this.setBlob(data, this.symbolByName.BinaryOntologyCodec);
    this.call('decodeOntologyBinary');
    this.setBlobSize(this.symbolByName.BinaryOntologyCodec, 0);
};

module.exports.prototype.saveImage = function() {
    return this.wasmInstance.exports.memory.buffer.slice(this.superPageByteAddress);
};

module.exports.prototype.loadImage = function(image) {
    const currentSize = this.wasmInstance.exports.memory.buffer.byteLength,
          newSize = this.superPageByteAddress+image.byteLength;
    if(currentSize < newSize)
        this.wasmInstance.exports.memory.grow(Math.ceil((newSize-currentSize)/this.chunkSize));
    this.setMemorySlice(image, this.superPageByteAddress);
};

module.exports.prototype.resetImage = function() {
    this.setMemorySlice(new Uint8Array(this.chunkSize), this.superPageByteAddress);
    this.call(this.initializerFunction+'WASM.cpp');
};

module.exports.prototype.env = {
    consoleLogString(basePtr, length) {
        console.log(utf8ArrayToString(this.getMemorySlice(basePtr, length)));
    },
    consoleLogInteger(value) {
        console.log(value);
    },
    consoleLogFloat(value) {
        console.log(value);
    }
};
module.exports.prototype.initializerFunction = '_GLOBAL__sub_I_';
module.exports.prototype.chunkSize = 65536;
module.exports.prototype.blobBufferSize = 4096;
module.exports.prototype.symbolByName = {
    Void: 0,
    PosX: 13,
    PosY: 14,
    BlobType: 15,
    Natural: 16,
    Integer: 17,
    Float: 18,
    UTF8: 19,
    BinaryOntologyCodec: 22
};
module.exports.prototype.queryMode = ['M', 'V', 'I'];
module.exports.prototype.queryMask = {};
for(let i = 0; i < 27; ++i)
    module.exports.prototype.queryMask[module.exports.prototype.queryMode[i%3] + module.exports.prototype.queryMode[Math.floor(i/3)%3] + module.exports.prototype.queryMode[Math.floor(i/9)%3]] = i;

module.exports.prototype.getMemorySlice = function(begin, length) {
    return new Uint8Array(this.wasmInstance.exports.memory.buffer.slice(begin, begin+length));
};

module.exports.prototype.setMemorySlice = function(slice, begin) {
    new Uint8Array(this.wasmInstance.exports.memory.buffer).set(slice, begin);
};

module.exports.prototype.readSymbolBlob = function(symbol) {
    const buffer = this.readBlob(symbol).buffer;
    return Array.prototype.slice.call(new Uint32Array(buffer));
};

module.exports.prototype.deserializeHRL = function(inputString, packageSymbol = 0) {
    const inputSymbol = this.createSymbol(), outputSymbol = this.createSymbol();
    this.setBlob(inputString, inputSymbol);
    const exception = this.call('deserializeHRL', inputSymbol, outputSymbol, packageSymbol);
    const result = this.readSymbolBlob(outputSymbol);
    this.unlinkSymbol(inputSymbol);
    this.unlinkSymbol(outputSymbol);
    return (exception) ? exception : result;
};

module.exports.prototype.call = function(name, ...params) {
    try {
        return this.wasmInstance.exports[name](...params);
    } catch(error) {
        console.log(name, ...params, error);
    }
};

},{}],2:[function(require,module,exports){
(function (process){
/* jslint node: true, esnext: true */
/* global document, window */
'use strict';

const WiredPanels = require('WiredPanels'),
      Symatem = require('../../SymatemWasm');

module.exports = function(element) {
    return new Promise(function(fullfill, reject) {
        if(typeof WebAssembly !== 'object') {
            reject();
            return;
        }
        this.fetchResource('js/Symatem.wasm', 'arraybuffer').then(function(arraybuffer) {
            new Symatem(new Uint8Array(arraybuffer)).then(function(symatemInstance) {
                this.symatem = symatemInstance;
                this.wiredPanels = new WiredPanels(element);
                this.panelIndex = new Map;
                this.labelIndex = new Map;
                this.symatem.linkedTriple = function(entity, attribute, value) {
                    if(!this.panelIndex.has(entity))
                        return;
                    const panel = this.panelIndex.get(entity);
                    for(let index = 0; index < panel.leftSide.length; ++index)
                        if(panel.leftSide[index].symbol == attribute && panel.rightSide[index].symbol == value)
                            return;
                    this.generateSegment(panel, attribute, value);
                    this.wiredPanels.syncPanel(panel);
                    this.wireSegment(panel, panel.leftSide.length-1);
                }.bind(this);
                this.symatem.unlinkedTriple = function(entity, attribute, value) {
                    if(!this.panelIndex.has(entity))
                        return;
                    const panel = this.panelIndex.get(entity);
                    for(let index = 0; index < panel.leftSide.length; ++index)
                        if(panel.leftSide[index].symbol == attribute && panel.rightSide[index].symbol == value) {
                            this.removeSegment(panel, index);
                            return;
                        }
                }.bind(this);
                this.symatem.releasedSymbol = this.hideSymbol.bind(this);
                element.ondblclick = function() {
                    const input = prompt('Blob:');
                    if(input == null || (input[0] != '"' && input.indexOf(';') > -1))
                        return;
                    const result = this.symatem.deserializeHRL(input);
                    if(result.length == 0)
                        this.showSymbols([this.symatem.createSymbol()]);
                    else
                        this.showSymbols((result[0]) ? result : [result]);
                    this.wiredPanels.syncGraph();
                }.bind(this);
                fullfill(this);
            }.bind(this));
        }.bind(this), function(error) {
            console.log(error);
        });
    }.bind(this));
}

module.exports.prototype.fetchResource = function(URL, type) {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', URL, true);
    xhr.responseType = type;
    xhr.send(null);
    return new Promise(function(fullfill, reject) {
        xhr.onload = function(event) {
            fullfill(event.target.response);
        };
        xhr.onerror = reject;
    });
};

module.exports.prototype.setBlob = function(blob, symbol) {
    this.symatem.setBlob(blob, symbol);
    if(!this.panelIndex.has(symbol))
        return;
    const label = this.getLabel(symbol);
    for(const segment of this.labelIndex.get(symbol))
        this.updateLabel(segment, label);
};

module.exports.prototype.getLabel = function(symbol, cap = 16) {
    let label = this.symatem.serializeBlob(symbol);
    if(cap > 0 && label.length > cap+1)
        label = label.substr(0, cap)+'…';
    return label;
};

module.exports.prototype.updateLabel = function(segment, label) {
    segment.label.textContent = label;
    if(label[0] == '#')
        segment.label.classList.add('disabled');
    else
        segment.label.classList.remove('disabled');
};

module.exports.prototype.addLabel = function(segment) {
    let label, set = this.labelIndex.get(segment.symbol);
    if(!set) {
        set = new Set([segment]);
        this.labelIndex.set(segment.symbol, set);
        label = this.getLabel(segment.symbol);
    } else {
        label = set.keys().next().value.label.textContent;
        set.add(segment);
    }
    this.updateLabel(segment, label);
};

module.exports.prototype.removeLabel = function(segment) {
    let set = this.labelIndex.get(segment.symbol);
    if(set) {
        set.delete(segment);
        if(set.size == 0)
            this.labelIndex.delete(segment.symbol);
    }
};

module.exports.prototype.plugInWire = function(type, element, dstSocket, wire) {
    let emptySocket, filledSocket, attribute, value;
    if(dstSocket.symbol !== undefined) {
        emptySocket = wire.srcSocket;
        filledSocket = dstSocket;
        if(emptySocket.symbol !== undefined)
            return false;
    } else {
        emptySocket = dstSocket;
        filledSocket = wire.srcSocket;
        if(filledSocket.symbol === undefined)
            return false;
    }
    const index = this.wiredPanels.getIndexOfSocket(emptySocket),
          coSocket = this.wiredPanels.getSocketAtIndex(emptySocket.panel, -index),
          dstPanel = this.panelIndex.get(filledSocket.symbol),
          entity = emptySocket.panel.symbol;
    if(coSocket.symbol !== undefined) {
        if(emptySocket.type == 'attribute') {
            attribute = filledSocket.symbol;
            value = coSocket.symbol;
        } else {
            attribute = coSocket.symbol;
            value = filledSocket.symbol;
        }
        if(this.symatem.queryCount(this.symatem.queryMask.MMM, entity, attribute, value) > 0)
            return false;
    }
    emptySocket.symbol = filledSocket.symbol;
    this.addLabel(emptySocket);
    if(dstPanel)
        this.wiredPanels.initializeWire({
            type: emptySocket.type,
            srcPanel: emptySocket.panel,
            dstPanel: dstPanel,
            srcSocket: emptySocket,
            dstSocket: this.wiredPanels.getSocketAtIndex(dstPanel, 0)
        });
    this.wiredPanels.syncGraph();
    if(coSocket.symbol !== undefined)
        this.symatem.linkTriple(entity, attribute, value);
    return true;
};

module.exports.prototype.showSymbols = function(symbols) {
    for(const entry of symbols) {
        const panel = (entry.symbol) ? entry : { symbol: entry };
        panel.type = 'entity';
        panel.leftSide = [];
        panel.rightSide = [];
        if(this.panelIndex.has(panel.symbol))
            continue;
        const result = this.symatem.queryArray(this.symatem.queryMask.MVV, panel.symbol, 0, 0);
        for(let i = 0; i < result.length; i += 2)
            this.generateSegment(panel, result[i], result[i+1]);
        this.wiredPanels.initializePanel(panel);
        this.panelIndex.set(panel.symbol, panel);
        this.addLabel(panel);
        panel.onactivation = function(type, element, node) {
            if(type == 'panels') {
                const string = prompt('Blob:', this.getLabel(node.symbol, null));
                if(string == null)
                    return;
                this.setBlob(this.symatem.deserializeBlob(string), node.symbol);
            } else
                this.hideSymbol(node.symbol);
            this.wiredPanels.syncGraph();
        }.bind(this);
        panel.ondeletion = function(type, element, panel) {
            this.symatem.unlinkSymbol(panel.symbol);
            this.wiredPanels.syncGraph();
        }.bind(this);
        panel.onwireconnect = function(type, element, panel, wire) {
            if(type == 'panels') {
                this.generateSegment(panel);
                this.wiredPanels.syncPanel(panel);
                this.wiredPanels.syncGraph();
                if(wire.type == 'attribute')
                    this.plugInWire(type, element, panel.leftSide[panel.leftSide.length-1], wire);
                else // if(wire.type == 'value')
                    this.plugInWire(type, element, panel.rightSide[panel.rightSide.length-1], wire);
            } else
                this.plugInWire(type, element, panel, wire);
        }.bind(this);
    }
    for(const pair of this.panelIndex) {
        const panel = pair[1];
        for(let index = 0; index < panel.leftSide.length; ++index)
            this.wireSegment(panel, index);
    }
};

module.exports.prototype.hideSymbol = function(symbol) {
    const panel = this.panelIndex.get(symbol);
    if(!panel)
        return false;
    this.removeLabel(panel);
    for(let index = 0; index < panel.leftSide.length; ++index) {
        this.removeLabel(panel.leftSide[index]);
        this.removeLabel(panel.rightSide[index]);
    }
    this.panelIndex.delete(symbol);
    this.wiredPanels.delete(panel);
    return true;
};

module.exports.prototype.hideAllSymbols = function() {
    for(const pair of this.panelIndex)
        this.wiredPanels.delete(pair[1]);
    this.panelIndex.clear();
    this.labelIndex.clear();
};

module.exports.prototype.socketActivationHandler = function(type, element, node) {
    if(node.symbol === undefined)
        return;
    this.showSymbols([node.symbol]);
    this.wiredPanels.syncGraph();
};

module.exports.prototype.socketDeletionHandler = function(type, element, socket) {
    const index = Math.abs(this.wiredPanels.getIndexOfSocket(socket))-1,
          leftSocket = socket.panel.leftSide[index],
          rightSocket = socket.panel.rightSide[index];
    if(leftSocket.symbol !== undefined && rightSocket.symbol !== undefined)
        this.symatem.unlinkTriple(socket.panel.symbol, leftSocket.symbol, rightSocket.symbol);
    else
        this.removeSegment(socket.panel, index);
    this.wiredPanels.syncGraph();
};

module.exports.prototype.generateSegment = function(panel, attribute, value) {
    panel.leftSide.push({
        type: 'attribute',
        symbol: attribute,
        onactivation: this.socketActivationHandler.bind(this),
        ondeletion: this.socketDeletionHandler.bind(this),
        onwireconnect: this.plugInWire.bind(this)
    });
    panel.rightSide.push({
        type: 'value',
        symbol: value,
        onactivation: this.socketActivationHandler.bind(this),
        ondeletion: this.socketDeletionHandler.bind(this),
        onwireconnect: this.plugInWire.bind(this)
    });
};

module.exports.prototype.wireSegment = function(panel, index) {
    const leftSocket = panel.leftSide[index],
          rightSocket = panel.rightSide[index],
          leftDstPanel = this.panelIndex.get(leftSocket.symbol),
          rightDstPanel = this.panelIndex.get(rightSocket.symbol);
    if(!leftSocket.label.textContent && leftSocket.symbol !== undefined)
        this.addLabel(leftSocket);
    if(!rightSocket.label.textContent && rightSocket.symbol !== undefined)
        this.addLabel(rightSocket);
    if(leftSocket.wiresPerPanel.size == 0 && leftDstPanel)
        this.wiredPanels.initializeWire({
            type: 'attribute',
            srcPanel: panel,
            dstPanel: leftDstPanel,
            srcSocket: leftSocket,
            dstSocket: this.wiredPanels.getSocketAtIndex(leftDstPanel, 0)
        });
    if(rightSocket.wiresPerPanel.size == 0 && rightDstPanel)
        this.wiredPanels.initializeWire({
            type: 'value',
            srcPanel: panel,
            dstPanel: rightDstPanel,
            srcSocket: rightSocket,
            dstSocket: this.wiredPanels.getSocketAtIndex(rightDstPanel, 0)
        });
};

module.exports.prototype.removeSegment = function(panel, index) {
    const leftSocket = panel.leftSide[index],
          rightSocket = panel.rightSide[index];
    this.removeLabel(leftSocket);
    this.removeLabel(rightSocket);
    leftSocket.deathFlag = true;
    rightSocket.deathFlag = true;
    this.wiredPanels.syncPanel(panel);
};

module.exports.prototype.saveImage = function() {
    const tmpTriples = [];
    for(const pair of this.panelIndex) {
        const posX = this.symatem.createSymbol(),
              posY = this.symatem.createSymbol();
        this.symatem.setBlob(pair[1].x, posX);
        this.symatem.setBlob(pair[1].y, posY);
        let triple = [pair[0], this.symatem.symbolByName.PosX, posX];
        this.symatem.linkTriple(triple[0], triple[1], triple[2]);
        tmpTriples.push(triple);
        triple = [pair[0], this.symatem.symbolByName.PosY, posY];
        this.symatem.linkTriple(triple[0], triple[1], triple[2]);
        tmpTriples.push(triple);
    }
    const file = new Blob([this.symatem.encodeOntologyBinary()], {type: 'octet/stream'}),
          url = URL.createObjectURL(file);
    for(const triple of tmpTriples)
        this.symatem.unlinkTriple(triple[0], triple[1], triple[2]);
    if(navigator.userAgent.toLowerCase().indexOf('firefox') > -1) {
        window.open(url, '_blank');
    } else {
        const a = document.createElement('a');
        a.href = url;
        a.download = 'Ontology';
        a.click();
    }
    URL.revokeObjectURL(url);
};

module.exports.prototype.loadImage = function(binary) {
    this.hideAllSymbols();
    this.symatem.resetImage();
    this.symatem.decodeOntologyBinary(binary);
    const panels = [], posXarray = this.symatem.queryArray(this.symatem.queryMask.VMV, 0, this.symatem.symbolByName.PosX, 0);
    for(let i = 0; i < posXarray.length; i += 2) {
        const posYarray = this.symatem.queryArray(this.symatem.queryMask.MMV, posXarray[i], this.symatem.symbolByName.PosY, 0);
        if(posYarray.length != 1)
            continue;
        const symbol = posXarray[i], posX = posXarray[i+1], posY = posYarray[0];
        this.symatem.unlinkTriple(symbol, this.symatem.symbolByName.PosX, posX);
        this.symatem.unlinkTriple(symbol, this.symatem.symbolByName.PosY, posY);
        panels.push({
            symbol: symbol,
            x: this.symatem.getBlob(posX),
            y: this.symatem.getBlob(posY)
        });
    }
    this.showSymbols(panels);
    this.wiredPanels.syncGraph();
};

if(process.browser)
    new module.exports(document.currentScript.parentNode).then(function(ontologyEditor) {
        const element = ontologyEditor.wiredPanels.svg.parentNode;
        ontologyEditor.fetchResource('Network.sym', 'text').then(function(codeInput) {
            ontologyEditor.hideAllSymbols();
            ontologyEditor.symatem.resetImage();
            const result = ontologyEditor.symatem.deserializeHRL(codeInput);
            ontologyEditor.showSymbols((result[0]) ? result : [result]);
            ontologyEditor.wiredPanels.syncGraph();
        });
        document.getElementById('saveImage').onclick = function(event) {
            ontologyEditor.saveImage();
        };
        element.addEventListener('dragover', function(event) {
            event.stopPropagation();
            event.preventDefault();
            event.dataTransfer.dropEffect = 'copy';
        }, false);
        element.addEventListener('drop', function(event) {
            event.stopPropagation();
            event.preventDefault();
            const input = event.dataTransfer || event.target;
            if(!input || !input.files || input.files.length != 1)
                return;
            const file = input.files[0], reader = new FileReader();
            reader.onload = function(event) {
                ontologyEditor.loadImage(new Uint8Array(reader.result));
            };
            reader.onerror = function(error) {
                console.log(error);
            };
            reader.readAsArrayBuffer(file);
        }, false);
    });

}).call(this,require('_process'))
},{"../../SymatemWasm":1,"WiredPanels":3,"_process":4}],3:[function(require,module,exports){
/* jslint node: true, esnext: true */
/* global document, window */
'use strict';

module.exports = function (parentElement) {
  while(parentElement.getElementsByClassName('fallback').length > 0)
    parentElement.removeChild(parentElement.getElementsByClassName('fallback')[0]);
  this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  parentElement.appendChild(this.svg);
  document.body.addEventListener('keydown', this.handleKeyboard.bind(this));
  this.svg.classList.add('WiredPanels');
  this.svg.onmousedown = function (event) {
    this.deselectAll();
    event.stopPropagation();
    return true;
  }.bind(this);
  this.svg.ontouchstart = function (event) {
    return this.svg.onmousedown(event.touches[0]);
  }.bind(this);
  this.svg.onmousemove = function (event) {
    if (!this.dragging)
      return false;
    this.draggingMoved = true;
    const rect = this.svg.getBoundingClientRect(),
          mouseX = event.pageX - rect.left - window.pageXOffset,
          mouseY = event.pageY - rect.top - window.pageYOffset;
    if (this.dragging.srcSocket) {
      if (!this.dragging.path) {
        this.initializeWire(this.dragging);
        this.dragging.path.setAttribute('pointer-events', 'none');
      }
      this.dragging.dstSocket.circle.x = mouseX;
      this.dragging.dstSocket.circle.y = mouseY;
      this.tickWire(this.dragging);
    } else {
      this.dragging.forEach(function (dragging, node) {
        node.x = mouseX - dragging.x;
        node.y = mouseY - dragging.y;
      }, this);
      this.stabilizeGraph();
    }
    event.stopPropagation();
    return true;
  }.bind(this);
  this.svg.ontouchmove = function (event) {
    return this.svg.onmousemove(event.touches[0]);
  }.bind(this);
  this.svg.onmouseup = function (event) {
    if (!this.dragging)
      return false;
    if (this.dragging.path) {
      this.selection.wires.delete(this.dragging);
      this.wires.delete(this.dragging);
      this.deleteElements([this.dragging.path]);
    } else {
      for (let panel of this.selection.panels)
        panel.rect.classList.remove('selected');
      this.selection.panels.clear();
    }
    delete this.dragging;
    event.stopPropagation();
    return true;
  }.bind(this);
  this.svg.ontouchend = function (event) {
    return this.svg.onmouseup(event.touches[0]);
  }.bind(this);
  this.svg.onmouseleave = function (event) {
    return this.svg.onmouseup(event);
  }.bind(this);

  const svgDefs = this.createElement('defs', this.svg);
  const blurFilter = this.createElement('filter', svgDefs);
  blurFilter.setAttribute('id', 'blurFilter');
  blurFilter.setAttribute('x', -10);
  blurFilter.setAttribute('y', -10);
  blurFilter.setAttribute('width', 20);
  blurFilter.setAttribute('height', 20);
  const feGaussianBlur = this.createElement('feGaussianBlur', blurFilter);
  feGaussianBlur.setAttribute('in', 'SourceGraphic');
  feGaussianBlur.setAttribute('result', 'blur');
  feGaussianBlur.setAttribute('stdDeviation', 3);
  const feComponentTransfer = this.createElement('feComponentTransfer', blurFilter);
  feComponentTransfer.setAttribute('in', 'blur');
  feComponentTransfer.setAttribute('result', 'brighter');
  const feFunc = this.createElement('feFuncA', feComponentTransfer);
  feFunc.setAttribute('type', 'linear');
  feFunc.setAttribute('slope', 2.5);
  const feMerge = this.createElement('feMerge', blurFilter);
  this.createElement('feMergeNode', feMerge).setAttribute('in', 'brighter');
  this.createElement('feMergeNode', feMerge).setAttribute('in', 'SourceGraphic');

  this.panelsGroup = this.createElement('g', this.svg);
  this.wiresGroup = this.createElement('g', this.svg);
  this.panels = new Set();
  this.springs = new Set();
  this.wires = new Set();
  this.selection = {
    sockets: new Set(),
    wires: new Set(),
    panels: new Set()
  };
  this.tickCount = 0;
};

module.exports.prototype.config = {
  socketRadius: 5,
  fontSize: 12,
  wireStyle: 'hybrid',
  headSocket: true,
  panelLines: true,
  panelWidth: 300,
  panelCornerRadius: 10,
  panelPadding: 12,
  panelMargin: 12,
  springLength: 200,
  springStiffness: 0.1,
  panelCollision: true,
  borderCollision: true
};

module.exports.prototype.handleKeyboard = function (event) {
  if (this.svg.parentNode.querySelector('svg:hover') == null || event.ctrlKey)
    return;
  event.stopPropagation();
  event.preventDefault();
  switch (event.keyCode) {
    case 8:
      this.iterateSelection(function(type, element, node) {
        if (node.ondeletion)
          node.ondeletion(type, element, node);
      });
      this.deselectAll();
      this.syncGraph();
      break;
    case 13:
      this.iterateSelection(function(type, element, node) {
        if (node.onactivation)
          node.onactivation(type, element, node);
      });
      break;
    case 37:
      break;
    case 38:
      break;
    case 39:
      break;
    case 40:
      break;
  }
};

module.exports.prototype.setHandlers = function (type, element, node) {
  element.onmousedown = function (event) {
    this.draggingMoved = false;
    const rect = this.svg.getBoundingClientRect(),
          mouseX = event.pageX - rect.left - window.pageXOffset,
          mouseY = event.pageY - rect.top - window.pageYOffset;
    if (event.shiftKey)
      this.setSelected(type, element, node, 'toggle');
    else switch (type) {
      case 'panels':
        this.setSelected(type, element, node, true);
        this.dragging = new Map();
        this.selection.panels.forEach(function (node) {
          let dragging = {
              x: mouseX - node.x,
              y: mouseY - node.y
          };
          this.dragging.set(node, dragging);
        }, this);
        break;
      case 'sockets':
        this.dragging = {type: node.type, srcSocket: node, dstSocket: {circle: {}}};
        break;
    }
    event.stopPropagation();
    return true;
  }.bind(this);
  element.ontouchstart = function (event) {
    return element.onmousedown(event.touches[0]);
  }.bind(this);
  element.onmouseup = function (event) {
    if (event.shiftKey)
      return true;
    if (!this.draggingMoved) {
      if (node.onactivation)
        node.onactivation(type, element, node);
    } else if (this.dragging && this.dragging.path) {
      if (node.onwireconnect)
        node.onwireconnect(type, element, node, this.dragging);
    }
  }.bind(this);
  element.ontouchstop = function (event) {
    return element.onmouseup(event.touches[0]);
  }.bind(this);
};

module.exports.prototype.createElement = function (tag, parentNode) {
  const element = document.createElementNS(this.svg.namespaceURI, tag);
  parentNode.appendChild(element);
  return element;
};

module.exports.prototype.setSelected = function (type, element, node, newValue) {
  const oldValue = this.selection[type].has(node);
  if (newValue == oldValue)
    return oldValue;
  if (newValue == 'toggle')
    newValue = !oldValue;
  if (newValue) {
    this.selection[type].add(node);
    element.classList.add('selected');
  } else {
    this.selection[type].delete(node);
    element.classList.remove('selected');
  }
  return newValue;
};

module.exports.prototype.iterateSelection = function (callback) {
  for (let socket of this.selection.sockets)
    callback('sockets', socket.circle, socket);
  for (let wire of this.selection.wires)
    callback('wires', wire.path, wire);
  for (let panel of this.selection.panels)
    callback('panels', panel.rect, panel);
};

module.exports.prototype.deselectAll = function () {
  this.iterateSelection(function(type, element, node) {
    element.classList.remove('selected');
  });
  this.selection.sockets.clear();
  this.selection.wires.clear();
  this.selection.panels.clear();
};

module.exports.prototype.getSocketAtIndex = function (panel, index) {
  if (index < 0)
    return panel.leftSide[-index-1];
  else if (index > 0)
    return panel.rightSide[index-1];
  else
    return panel;
};

module.exports.prototype.getIndexOfSocket = function (socket) {
  if (socket.panel === socket)
    return 0;
  for (let i = 0; i < socket.panel.leftSide.length; ++i)
    if (socket.panel.leftSide[i] === socket)
      return -i - 1;
  for (let i = 0; i < socket.panel.rightSide.length; ++i)
    if (socket.panel.rightSide[i] === socket)
      return i + 1;
  return undefined;
};

module.exports.prototype.connectPanels = function (srcPanel, dstPanel) {
  if (srcPanel === dstPanel)
    return;
  let spring = srcPanel.springs.get(dstPanel);
  if (spring)
    ++spring.referenceCount;
  else {
    spring = {
      referenceCount: 1,
      srcPanel: srcPanel,
      dstPanel: dstPanel
    };
    srcPanel.springs.set(dstPanel, spring);
    dstPanel.springs.set(srcPanel, spring);
    this.springs.add(spring);
  }
  return spring;
};

module.exports.prototype.disconnectPanels = function (srcPanel, dstPanel) {
  if (srcPanel === dstPanel)
    return;
  const spring = srcPanel.springs.get(dstPanel);
  if (spring.referenceCount > 1)
    --spring.referenceCount;
  else {
    srcPanel.springs.delete(dstPanel);
    dstPanel.springs.delete(srcPanel);
    this.springs.delete(spring);
  }
};

module.exports.prototype.connectSocket = function (wire, srcSocket, dstPanel) {
  let set;
  if (!srcSocket.wiresPerPanel.has(dstPanel)) {
    set = new Set();
    srcSocket.wiresPerPanel.set(dstPanel, set);
  } else {
    set = srcSocket.wiresPerPanel.get(dstPanel);
    if (set.has(wire))
      return false;
  }
  set.add(wire);
  return true;
};

module.exports.prototype.disconnectSocket = function (wire, srcSocket, dstPanel) {
  if (!srcSocket.wiresPerPanel.has(dstPanel))
    return false;
  const set = srcSocket.wiresPerPanel.get(dstPanel);
  if (!set.has(wire))
    return false;
  set.delete(wire);
  if (set.size === 0)
    srcSocket.wiresPerPanel.delete(dstPanel);
  return true;
};

module.exports.prototype.initializeWire = function (wire) {
  if (wire.srcPanel && wire.dstPanel) {
    if (!this.connectSocket(wire, wire.srcSocket, wire.dstPanel) ||
        !this.connectSocket(wire, wire.dstSocket, wire.srcPanel))
      return;
    this.connectPanels(wire.srcPanel, wire.dstPanel);
  }
  wire.path = this.createElement('path', this.wiresGroup);
  wire.path.classList.add('wire');
  wire.path.classList.add('fadeIn');
  wire.path.classList.add(wire.type);
  this.setHandlers('wires', wire.path, wire);
  this.wires.add(wire);
  this.dirtyFlag = true;
  return wire;
};

module.exports.prototype.initializePanel = function (panel) {
  const rect = this.svg.getBoundingClientRect();
  panel.springs = new Map();
  if (!panel.x)
    panel.x = rect.width*Math.random();
  if (!panel.y)
    panel.y = rect.height*Math.random();
  this.syncPanel(panel);
  this.panels.add(panel);
  this.dirtyFlag = true;
  return panel;
};

module.exports.prototype.delete = function (element) {
  element.deathFlag = true;
  this.dirtyFlag = true;
};

module.exports.prototype.tickSocket = function (posX, posY, socket) {
  let element = socket.circle;
  element.x = posX + parseInt(element.getAttribute('cx'));
  element.y = posY + parseInt(element.getAttribute('cy'));
};

module.exports.prototype.tickWire = function (wire) {
  const src = wire.srcSocket.circle, dst = wire.dstSocket.circle;
  switch (this.config.wireStyle) {
    case 'straight':
      wire.path.setAttribute('d', 'M' + src.x + ',' + src.y + 'L' + dst.x + ',' + dst.y);
      break;
    case 'vertical':
      wire.path.setAttribute('d', 'M' + src.x + ',' + src.y + 'C' + dst.x + ',' + src.y + ' ' + src.x + ',' + dst.y + ' ' + dst.x + ',' + dst.y);
      break;
    case 'horizontal':
      wire.path.setAttribute('d', 'M' + src.x + ',' + src.y + 'C' + src.x + ',' + dst.y + ' ' + dst.x + ',' + src.y + ' ' + dst.x + ',' + dst.y);
      break;
    case 'hybrid':
      if (Math.abs(src.x - dst.x) < Math.abs(src.y - dst.y))
        wire.path.setAttribute('d', 'M' + src.x + ',' + src.y + 'C' + dst.x + ',' + src.y + ' ' + src.x + ',' + dst.y + ' ' + dst.x + ',' + dst.y);
      else
        wire.path.setAttribute('d', 'M' + src.x + ',' + src.y + 'C' + src.x + ',' + dst.y + ' ' + dst.x + ',' + src.y + ' ' + dst.x + ',' + dst.y);
      break;
    case 'gravity':
      const diffX = dst.x - src.x;
      const maxY = Math.max(dst.y, src.y) + 20;
      wire.path.setAttribute('d', 'M' + src.x + ',' + src.y + 'C' + (src.x + diffX * 0.25) + ',' + maxY + ' ' + (src.x + diffX * 0.75) + ',' + maxY + ' ' + dst.x + ',' + dst.y);
      break;
  }
};

module.exports.prototype.panelMinX = function (panel) {
  return panel.x - panel.width / 2 - this.config.panelMargin;
};

module.exports.prototype.panelMaxX = function (panel) {
  return panel.x + panel.width / 2 + this.config.panelMargin;
};

module.exports.prototype.panelMinY = function (panel) {
  return panel.y - panel.height / 2 - this.config.panelMargin;
};

module.exports.prototype.panelMaxY = function (panel) {
  return panel.y + panel.height / 2 + this.config.panelMargin;
};

module.exports.prototype.tickGraph = function () {
  if(--this.tickCount == 0)
    window.clearInterval(this.animationTimer);

  if (this.config.springStiffness != 0)
    for (const spring of this.springs) {
      let vecX = spring.srcPanel.x - spring.dstPanel.x,
          vecY = spring.srcPanel.y - spring.dstPanel.y;
      const distance = Math.max(1, Math.sqrt(vecX * vecX + vecY * vecY)),
            displacement = this.config.springLength - distance,
            factor = this.config.springStiffness * displacement / distance;
      vecX *= factor;
      vecY *= factor;
      spring.srcPanel.x += vecX;
      spring.srcPanel.y += vecY;
      spring.dstPanel.x -= vecX;
      spring.dstPanel.y -= vecY;
  }

  if (this.config.panelCollision) {
    let i = 0;
    for (const panelA of this.panels) {
      let j = 0;
      for (const panelB of this.panels) {
          if (i <= j)
            break;
          let overlapX = Math.min(this.panelMaxX(panelA), this.panelMaxX(panelB)) - Math.max(this.panelMinX(panelA), this.panelMinX(panelB)),
              overlapY = Math.min(this.panelMaxY(panelA), this.panelMaxY(panelB)) - Math.max(this.panelMinY(panelA), this.panelMinY(panelB));
          if (overlapX <= 0 || overlapY <= 0)
            continue;
          if (Math.abs(overlapX) < Math.abs(overlapY)) {
            if (panelA.x < panelB.x)
              overlapX *= -1;
            panelA.x += overlapX;
            panelB.x -= overlapX;
          } else {
            if (panelA.y < panelB.y)
              overlapY *= -1;
            panelA.y += overlapY;
            panelB.y -= overlapY;
          }
          ++j;
      }
      ++i;
    }
  }

  if (this.config.borderCollision) {
    const rect = this.svg.getBoundingClientRect();
    for (const panel of this.panels) {
      if (this.panelMinX(panel) < 0)
        panel.x -= this.panelMinX(panel);
      else if (this.panelMaxX(panel) > rect.width)
        panel.x -= this.panelMaxX(panel) - rect.width;
      if (this.panelMinY(panel) < 0)
        panel.y -= this.panelMinY(panel);
      else if (this.panelMaxY(panel) > rect.height)
        panel.y -= this.panelMaxY(panel) - rect.height;
    }
  }

  for (const panel of this.panels) {
    const posX = panel.x - panel.width / 2,
          posY = panel.y - panel.height / 2;
    panel.group.setAttribute('transform', 'translate(' + posX + ', ' + posY + ')');
    if (panel.circle)
      this.tickSocket(posX, posY, panel);
    for (let i = 0; i < panel.leftSide.length; ++i)
      this.tickSocket(posX, posY, panel.leftSide[i]);
    for (let i = 0; i < panel.rightSide.length; ++i)
      this.tickSocket(posX, posY, panel.rightSide[i]);
  }

  for (const wire of this.wires)
    this.tickWire(wire);
};

module.exports.prototype.deleteSocket = function (socket) {
  this.dirtyFlag = true;
  this.selection.sockets.delete(socket);
  for (const pair of socket.wiresPerPanel)
    for (const wire of pair[1])
      wire.deathFlag = true;
};

module.exports.prototype.syncPanelSide = function (panel, side, isLeft) {
  for (let i = 0; i < side.length; ++i) {
    const socket = side[i];
    if (socket.deathFlag) {
      this.deleteSocket(socket);
      side.group.removeChild(side.group.childNodes[i * 2 + 1]);
      side.group.removeChild(side.group.childNodes[i * 2]);
      side.splice(i, 1);
      --i;
      continue;
    }

    if (!socket.circle) {
      socket.circle = this.createElement('circle', side.group);
      socket.circle.classList.add('socket');
      socket.circle.classList.add(socket.type);
      socket.circle.setAttribute('r', this.config.socketRadius);
      socket.label = this.createElement('text', side.group);
      socket.label.setAttribute('text-anchor', (isLeft) ? 'start' : 'end');
      this.setHandlers('sockets', socket.circle, socket);
      socket.wiresPerPanel = new Map();
      socket.panel = panel;
    }

    const posY = (i + 1) * this.config.panelPadding * 2;
    socket.circle.x = Math.round((isLeft) ? this.config.panelPadding : panel.width - this.config.panelPadding);
    socket.circle.y = Math.round(posY + this.config.panelPadding);
    socket.circle.setAttribute('cx', socket.circle.x);
    socket.circle.setAttribute('cy', socket.circle.y);
    socket.label.setAttribute('x', Math.round((isLeft) ? this.config.panelPadding * 2 : panel.width - this.config.panelPadding * 2));
    socket.label.setAttribute('y', Math.round(posY + this.config.panelPadding + this.config.fontSize * 0.4));
  }
};

module.exports.prototype.syncPanel = function (panel) {
  if (!panel.group) {
    panel.group = this.createElement('g', this.panelsGroup);
    panel.group.classList.add('fadeIn');

    panel.rect = this.createElement('rect', panel.group);
    panel.rect.classList.add('panel');
    panel.rect.classList.add(panel.type);
    panel.rect.setAttribute('rx', this.config.panelCornerRadius);
    panel.rect.setAttribute('ry', this.config.panelCornerRadius);
    this.setHandlers('panels', panel.rect, panel);
    panel.wiresPerPanel = new Map();
    panel.panel = panel;

    if (this.config.headSocket) {
      panel.circle = this.createElement('circle', panel.group);
      panel.circle.classList.add('socket');
      panel.circle.classList.add(panel.type);
      panel.circle.y = Math.round(-this.config.panelPadding);
      panel.circle.setAttribute('cy', panel.circle.y);
      panel.circle.setAttribute('r', this.config.socketRadius);
      this.setHandlers('sockets', panel.circle, panel);
    }

    panel.label = this.createElement('text', panel.group);
    panel.label.setAttribute('text-anchor', 'middle');
    panel.label.setAttribute('y', Math.round(this.config.panelPadding + this.config.fontSize * 0.4));
    panel.label.textContent = 'undefined';

    panel.leftSide.group = this.createElement('g', panel.group);
    panel.rightSide.group = this.createElement('g', panel.group);
    if (this.config.panelLines) {
      panel.lines = [];
      panel.lines.group = this.createElement('g', panel.group);
      panel.lines.group.classList.add('panel');
      panel.lines.group.classList.add(panel.type);
    }
  }

  panel.width = this.config.panelWidth;
  this.syncPanelSide(panel, panel.leftSide, true);
  this.syncPanelSide(panel, panel.rightSide, false);
  const socketCount = Math.max(panel.leftSide.length, panel.rightSide.length);
  panel.height = (socketCount + 1) * this.config.panelPadding * 2;
  panel.rect.setAttribute('width', panel.width);
  panel.rect.setAttribute('height', panel.height);
  const halfWidth = Math.round(panel.width / 2);
  if (panel.circle)
    panel.circle.setAttribute('cx', halfWidth);
  panel.label.setAttribute('x', halfWidth);

  if (panel.lines) {
    for (let i = panel.lines.group.childNodes.length - 1; i >= socketCount; --i)
      panel.lines.group.removeChild(panel.lines.group.childNodes[i]);
    panel.lines.splice(socketCount);

    for (let i = panel.lines.group.childNodes.length; i < socketCount; ++i) {
      const posY = (i + 1) * this.config.panelPadding * 2;
      panel.lines[i] = this.createElement('path', panel.lines.group);
      panel.lines[i].setAttribute('d', 'M0,' + posY + 'h' + panel.width);
      panel.lines[i].classList.add('noHover');
    }
  }

  return panel;
};

module.exports.prototype.stabilizeGraph = function () {
  if(this.tickCount > 0)
    return;
  this.tickCount = 20;
  this.animationTimer = window.setInterval(this.tickGraph.bind(this), 20);
};

module.exports.prototype.syncGraph = function () {
  if (!this.dirtyFlag)
    return;
  this.dirtyFlag = false;

  let trash = new Set();
  for (const panel of this.panels) {
    if (!panel.deathFlag)
      continue;
    if (panel.circle)
      this.deleteSocket(panel);
    for (let i = 0; i < panel.leftSide.length; ++i)
      this.deleteSocket(panel.leftSide[i]);
    for (let i = 0; i < panel.rightSide.length; ++i)
      this.deleteSocket(panel.rightSide[i]);
    trash.add(panel.group);
    this.panels.delete(panel);
    this.selection.panels.delete(panel);
  }

  for (const wire of this.wires) {
    if (!wire.deathFlag)
      continue;
    if (wire.srcPanel && wire.dstPanel) {
      this.disconnectSocket(wire, wire.srcSocket, wire.dstPanel);
      this.disconnectSocket(wire, wire.dstSocket, wire.srcPanel);
      this.disconnectPanels(wire.srcPanel, wire.dstPanel);
    }
    trash.add(wire.path);
    this.wires.delete(wire);
    this.selection.wires.delete(wire);
  }

  this.deleteElements(trash);
  this.stabilizeGraph();
};

module.exports.prototype.deleteElements = function (trash) {
  for (const element of trash) {
    element.classList.remove('fadeIn');
    element.classList.add('fadeOut');
  }
  window.setTimeout(function () {
    for (const element of trash)
      element.parentNode.removeChild(element);
  }.bind(this), 250);
};

},{}],4:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}]},{},[2]);
