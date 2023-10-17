const buffer = require('buffer');
const crypto = require('crypto');

function pbkdf2Async(password: string, salt: string, iterations: Number, keylen: Number, digest: string) {
    return new Promise( (res, rej) => {
        crypto.pbkdf2(password, salt, iterations, keylen, digest, (err: any, key: any) => {
            err ? rej(err) : res(key);
        });
    });
}

const aes256gcm = (key: any) => {
  const ALGO = 'aes-256-gcm';

  const encrypt = (str: any) => {
    const iv = new Buffer(crypto.randomBytes(12), 'utf8');
    const cipher = crypto.createCipheriv(ALGO, key, iv);

    let enc = cipher.update(str, 'utf8', 'base64');
    enc += cipher.final('base64');
    return [enc, iv.toString('base64'), cipher.getAuthTag().toString('base64')];
  };

  const decrypt = (enc: any, iv: any, authTag: any) => {
    const decipher = crypto.createDecipheriv(ALGO, key, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(authTag, 'base64'));
    let str = decipher.update(enc, 'base64', 'utf8');
    str += decipher.final('utf8');
    return str;
  };

  return {
    encrypt,
    decrypt,
  };
};

import { normalizePath, Notice, TFolder, Setting, moment } from "obsidian";
import { MarkdownView, TextFileView, WorkspaceLeaf } from 'obsidian';

export const VIEW_TYPE_ENCRYPTED_FILE = "encrypted-file-view";

export class EncryptedFileView extends MarkdownView {
	private encData: string = "";
	private shouldUpdate: boolean = false;
	private aesCipher: any = null;
	
	constructor(leaf: WorkspaceLeaf, aesCipher: any) {
		super(leaf);
		this.aesCipher = aesCipher;
	}

	onSwitchView(e: any) {
		this.shouldUpdate = false;
		new Notice('unsupported: mode switch');
		this.leaf.detach();
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
			new Notice('unsupported: reading mode');
			this.leaf.detach();
			return;
		}

		if(!clear) {
			this.shouldUpdate = false;
			new Notice('unsupported: 1 file with multiple tabs');
			this.leaf.detach();
			return;
		}

		try {
			let encryptedData = JSON.parse(data);
			const plaintext = this.aesCipher.decrypt(encryptedData.ciphertext, encryptedData.iv, encryptedData.tag);

			this.editor.setValue(plaintext);
			this.shouldUpdate = true;
		} catch(e) {
			this.shouldUpdate = false;
			console.log(e);
			new Notice('decryption failed: invalid password');
			this.leaf.detach();
		}
	}

	getViewData(): string {
		if(this.shouldUpdate) {
			try {
				if(this.aesCipher) {
					let [ciphertext, iv, tag] = this.aesCipher.encrypt(this.editor.getValue());
					
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

export default class MyPlugin extends Plugin {
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
		const ribbonIconEl = this.addRibbonIcon('lock', 'new encrypted note', (evt: MouseEvent) => {
			this.createEncryptedNote();
		});
		ribbonIconEl.addClass('globaloe-new-encrypted-note');

		this.registerExtensions(['aes256'], VIEW_TYPE_ENCRYPTED_FILE);

		new InputPasswordModal(this.app, async (password) => {
			const key = await pbkdf2Async(password, '7f2ea27bd475702540c5211aed17904202a3ac06b0e87fdd8fcdec960a0fe388', 1000000, 32, 'sha512');
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

		const pwChecker = (ev: Event | null) => {
			ev?.preventDefault();

			this.password = pwInputEl.value;
			this.close();
		}

		pwInputEl.addEventListener('keypress', (event) => {
			if (event.key === 'Enter') {
				pwChecker(null);
			}
		});
	}

	onClose() {
		const { contentEl } = this;
		contentEl.empty();

		this.onSubmit(this.password);
	}
}
