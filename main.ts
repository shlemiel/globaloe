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
import { defaultKeymap, indentWithTab } from "@codemirror/commands";
import { EditorView, highlightActiveLine, highlightActiveLineGutter, highlightSpecialChars, keymap, lineNumbers, rectangularSelection } from '@codemirror/view'
import { EditorState } from '@codemirror/state';
import { MarkdownView, TextFileView, WorkspaceLeaf } from 'obsidian';

export const VIEW_TYPE_ENCRYPTED_FILE = "encrypted-file-view";

export class EncryptedFileView extends MarkdownView {
	private aesCipher: any = null;
	private plaintext: string = '';
	private editorView: any = null;
	
	constructor(leaf: WorkspaceLeaf, aesCipher: any) {
		super(leaf);
		this.aesCipher = aesCipher;
	}
	
	canAcceptExtension(extension: string): boolean {
		return extension == 'aes256';
	}

	getViewType() {
		return VIEW_TYPE_ENCRYPTED_FILE;
	}

	override setViewData(data: string, clear: boolean): void {
		if (clear) {
			if(data != '') {
				try {
					let encrypted_data = JSON.parse(data);
					const plaintext = this.aesCipher.decrypt(encrypted_data.ciphertext, encrypted_data.iv, encrypted_data.tag);
					this.editor.setValue(plaintext);
				} catch(e) {
					this.leaf.detach();
					new Notice('Invalid password / Unsupported file format');
					console.log(e);
					return;
				}
			} else {
				this.editor.setValue("");
			}
		} else {
			this.leaf.detach();
			new Notice('Unsupported');
		}
	}

	override getViewData(): string {
		for(let i = 0; i < 5; i++) {
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

		return "ENCRYPTION FAILED";
	}

	override clear(): void {
	}
}

import { App, Editor, Modal, Plugin } from 'obsidian';

export default class MyPlugin extends Plugin {
	private aesCipher: any;

	private createEncryptedNote() {
		try {
			const newFilename = moment().format( `YYYYMMDD hhmmss[.aes256]`);
			
			let newFileFolder : TFolder;
			const activeFile = this.app.workspace.getActiveFile();

			if (activeFile != null){
				newFileFolder = this.app.fileManager.getNewFileParent(activeFile.path);
			} else {
				newFileFolder = this.app.fileManager.getNewFileParent('');
			}

			const newFilepath = normalizePath(newFileFolder.path + "/" + newFilename);
			
			this.app.vault.create(newFilepath,'').then(async f => {
				const leaf = this.app.workspace.getLeaf(true);
				await leaf.openFile(f);
			}).catch(reason => {
				new Notice(reason);
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
			const key = await pbkdf2Async(password, '7f2ea27bd475702540c5211aed17904202a3ac06b0e87fdd8fcdec960a0fe388', 100000, 32, 'sha512');
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
