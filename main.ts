const subtle = crypto.subtle;
const JsCrypto = require('jscrypto');

const b64tou8 = (x: string) => Uint8Array.from(atob(x), c => c.charCodeAt(0));

async function pbkdf2Async(password: string, salt: string, iterations: number) {
    const ec = new TextEncoder();
    const keyMaterial = await subtle.importKey('raw', ec.encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-512', salt: ec.encode(salt), iterations: iterations }, keyMaterial, { name: 'AES-GCM', length: 256, }, true, ['encrypt', 'decrypt']);
    const exported = new JsCrypto.Word32Array(new Uint8Array(await subtle.exportKey("raw", key)));
    return exported;
}

const aes256gcm = (key: any) => {
  const encrypt = (msg: any, origIv: any) => {
    let iv = crypto.getRandomValues(new Uint8Array(12));
    if(origIv)
        iv = b64tou8(origIv);

    iv = new JsCrypto.Word32Array(iv);
    msg = JsCrypto.Utf8.parse(msg);

    let encryptedData = JsCrypto.AES.encrypt(msg, key, {iv: iv, mode: JsCrypto.mode.GCM});
    let ciphertext = encryptedData.cipherText;
    let authTag = JsCrypto.mode.GCM.mac(JsCrypto.AES, key, iv, JsCrypto.Word32Array([]), ciphertext, 16);
    let encryptedPayload = encryptedData.toString();

    return [encryptedPayload, JsCrypto.Base64.stringify(iv), JsCrypto.Base64.stringify(authTag)];
  };

  const decrypt = (encryptedPayload: any, iv: any, authTag: any) => {
    iv = JsCrypto.Base64.parse(iv);
    let decryptedData = JsCrypto.AES.decrypt(encryptedPayload, key, {iv: iv, mode: JsCrypto.mode.GCM});

    let ciphertext = JsCrypto.formatter.OpenSSLFormatter.parse(encryptedPayload).cipherText;
    if(authTag !== JsCrypto.Base64.stringify(JsCrypto.mode.GCM.mac(JsCrypto.AES, key, iv, JsCrypto.Word32Array([]), ciphertext))) {
        throw new Error('authentication fail');
    }

    return JsCrypto.Utf8.stringify(decryptedData);
  };

  return {
    encrypt,
    decrypt,
  };
};

import { normalizePath, Notice, TFolder, Setting, moment } from "obsidian";
import { ViewState, MarkdownView, TextFileView, WorkspaceLeaf } from 'obsidian';

export const VIEW_TYPE_ENCRYPTED_FILE = "encrypted-file-view";

export class EncryptedFileView extends MarkdownView {
	private encData: string = "";
	private shouldUpdate: boolean = false;
	private aesCipher: any = null;
	private origIv: any = "";
	
	constructor(leaf: WorkspaceLeaf, aesCipher: any) {
        let origSetViewState = leaf.setViewState;
        leaf.setViewState = function(viewState: ViewState, eState?: any): Promise<void> {
            if((viewState.state.file && viewState.state.file.endsWith(".aes256")) && viewState.type !== VIEW_TYPE_ENCRYPTED_FILE || (viewState.state.mode && viewState.state.mode !== 'source') || (viewState.state.source && viewState.state.source !== false)) {
                this.detach();
                new Notice('unsupported: reading or unencrypted mode');
                return new Promise((resolve) => { setTimeout(resolve, 0); });
            } else {
                return origSetViewState.apply(this, [viewState, eState]);
            }
        };

		super(leaf);
		this.aesCipher = aesCipher;
	}

	canAcceptExtension(extension: string): boolean {
		return extension == 'aes256';
	}

	getViewType() {
		return VIEW_TYPE_ENCRYPTED_FILE;
	}

	setViewData(data: string, clear: boolean): void {
		this.encData = data;

		if(this.getState().mode != 'source') {
			this.shouldUpdate = false;
			this.leaf.detach();
			new Notice('unsupported: reading mode');
			return;
		}

		if(!clear) {
			this.shouldUpdate = false;
			this.leaf.detach();
			new Notice('unsupported: 1 file with multiple tabs');
			return;
		}

		try {
			let encryptedData = JSON.parse(data);
			const plaintext = this.aesCipher.decrypt(encryptedData.ciphertext, encryptedData.iv, encryptedData.tag);
			this.origIv = encryptedData.iv;

			this.editor.setValue(plaintext);
			this.shouldUpdate = true;
		} catch(e) {
			this.shouldUpdate = false;
			this.leaf.detach();
			new Notice('decryption failed: invalid password');
		}
	}

	getViewData(): string {
		if(this.shouldUpdate) {
			try {
				if(this.aesCipher) {
					let [ciphertext, iv, tag] = this.aesCipher.encrypt(this.editor.getValue(), this.origIv);
					
					const encData = JSON.stringify({
						iv: iv,
						tag: tag,
						ciphertext: ciphertext,
					});

					return encData;
				}
			} catch(e){
				console.error(e);
				new Notice(e, 10000);
			}
		}

		return this.encData;
	}
}

import { App, Editor, Modal, Plugin } from 'obsidian';

export default class GlobalMarkdownEncrypt extends Plugin {
	private aesCipher: any;

	private createEncryptedNote() {
		try {
			const newFilename = moment().format(`YYYYMMDD hhmmss[.aes256]`);
			
			const activeFile = this.app.workspace.getActiveFile();
			let newFileFolder: TFolder = this.app.fileManager.getNewFileParent(activeFile ? activeFile.path : '');

			const newFilepath = normalizePath(newFileFolder.path + "/" + newFilename);

			let [ciphertext, iv, tag] = this.aesCipher.encrypt("");
			
			const encData = JSON.stringify({
				iv: iv,
				tag: tag,
				ciphertext: ciphertext,
			});

			this.app.vault.create(newFilepath,encData).then(async f => {
				const leaf = this.app.workspace.getLeaf(true);

				await leaf.openFile(f);
			}).catch(e => {
				new Notice(e);
			});

		} catch(e) {
			console.error(e);
			new Notice(e);
		}
	}

	async onload() {
		const ribbonIconEl = this.addRibbonIcon('file-lock-2', 'new encrypted note', (evt: MouseEvent) => {
			this.createEncryptedNote();
		});
		ribbonIconEl.addClass('gme-new-encrypted-note');

		this.registerExtensions(['aes256'], VIEW_TYPE_ENCRYPTED_FILE);

		new InputPasswordModal(this.app, async (password) => {
			const key = await pbkdf2Async(password, '7f2ea27bd475702540c5211aed17904202a3ac06b0e87fdd8fcdec960a0fe388', 1000000);
			this.aesCipher = aes256gcm(key);
			this.registerView(VIEW_TYPE_ENCRYPTED_FILE, (leaf) => new EncryptedFileView(leaf, this.aesCipher));
		}).open();
	}

	onunload() {

	}
}

class InputPasswordModal extends Modal {
	onSubmit: (password: string) => void;
	password: string;

	constructor(app: App, onSubmit: (password: string) => void) {
		super(app);
		this.onSubmit = onSubmit;
	}

	onOpen() {
		const { contentEl } = this;
		contentEl.empty();

		contentEl.createEl("h2", { text: "note encryption password" });

		const inputPwContainerEl = contentEl.createDiv();
		inputPwContainerEl.style.marginBottom = '1em';
		const pwInputEl = inputPwContainerEl.createEl('input', { type: 'input', value: '' });
		pwInputEl.placeholder = "password";
		pwInputEl.style.width = '100%';
		pwInputEl.focus();

		const commitPassword = () => {
			this.password = pwInputEl.value;
			this.close();
		}

		pwInputEl.addEventListener('keypress', (event) => {
			if (event.key === 'Enter') {
				commitPassword();
			}
		});
	}

	onClose() {
		const { contentEl } = this;
		contentEl.empty();

        if(this.password)
            this.onSubmit(this.password);
	}
}
