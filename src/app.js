

let prng = null;


class App {
  constructor() {
    this.encryption_key = null;
    this.selected_tab_index = 0;
    this.unsaved_changes = false;
    this.state = 'init';
  }

  setup() {
    this.change_state(
      this.has_password_verification_ciphertext() ?
        'locked' : 'set_initial_password');
    for(const [tab_index, tab_node]
        of [...this.elt('tab_bar').children].entries())
      tab_node.onclick = (() => this.handle_tab_click(tab_index)).bind(this);
    this.elt('set_password_button').onclick = this.handle_set_password_button.bind(this);
    this.elt('enter_password_button').onclick = this.handle_enter_password_button.bind(this);
    this.elt('edit_tab_command').onclick = this.handle_edit_tab_command.bind(this);
    this.elt('lock_command').onclick = this.handle_lock_command.bind(this);
    this.elt('download_changes_command').onclick = this.handle_download_changes_command.bind(this);
    this.elt('save_changes_button').onclick = this.handle_save_changes_command.bind(this);
    this.elt('cancel_changes_button').onclick = this.handle_cancel_edit_tab_command.bind(this);
    this.elt('copy_cleartext_command').onclick = this.handle_copy_cleartext.bind(this);
    // this.elt('copy_ciphertext_command').onclick = this.handle_copy_ciphertext.bind(this);
    this.elt('file_upload_button').onclick = this.handle_upload_file.bind(this);
    this.elt('change_password_command').onclick = this.handle_change_password_command.bind(this);

    window.addEventListener('keydown', this.handle_key_down.bind(this));

    this.update_dom();
  }

  debug() {
    const n = 0xffffffff;
    alert(n >> 4);
    alert(0xffffff);
  }

  is_text_tab_index(tab_index) {
    // TODO: fix this
    return tab_index < 3;
  }

  is_files_tab_index(tab_index) {
    return tab_index === 3;
  }

  // Ctrl-key shortcuts.
  handle_key_down(event) {
    const key = event.key;
    let handled = true;
    if(event.ctrlKey) {
      const tabswitch_keymap = {
        '1': 0, 'n': 0,
        '2': 1, 'p': 1,
        '3': 2, 'o': 2,
        '4': 3, 'f': 3
      };
      const tab_index = tabswitch_keymap[key];
      if(tab_index !== undefined)
        this.switch_to_tab_index(tab_index);
      else if(key === 'e')
        this.handle_edit_tab_command();
      else if(key === 'd')  // TODO: remove
        this.debug();
      else
        handled = false;
      if(handled)
        event.preventDefault();
      
      // TODO:
      // Ctrl+c: Copy plaintext (maybe don't do this, for security)
      // Ctrl+s: Save (Download) chages
      // Ctrl+l: Lock
    }
  }

  handle_tab_click(tab_index) {
    this.switch_to_tab_index(tab_index);
    return false;
  }

  switch_to_tab_index(tab_index) {
    if(this.state === 'unlocked') {
      this.selected_tab_index = tab_index;
      this.update_dom();
      this.update_tab_content();
    }
  }

  handle_set_password_button() {
    const password = this.elt('set_password_input').value;
    const password_verify = this.elt('set_password_verify_input').value;
    this.elt('set_password_input').value = '';  // clear password
    this.elt('set_password_verify_input').value = '';
    const verification_matches = password === password_verify;
    this.show_or_hide_elt(
      'passwords_do_not_match_error', !verification_matches);
    if(verification_matches) {
      this.set_password(password);
      this.update_password_verification_ciphertext();
      this.change_state('unlocked');
    }
    return false;
  }

  // "Login" with encryption password.
  handle_enter_password_button() {
    const password = this.elt('password_input').value ?? '';
    if(password.length === 0) {
      alert('Please enter your encryption password');
      return false;
    }
    this.elt('password_input').value = '';
    this.set_password(password);
    const verify_result = this.verify_password();
    switch(verify_result) {
    case 'no_password':
      // Shouldn't happen.
      alert('Invalid password');
      return false;
    case 'unverified':
      alert('This document does not contain a password verification field.  Proceeding without verification.  Data will be decrypted to random garbage if the wrong password has been entered.');
      return false;
    case 'verification_failed':
      if(!confirm('Invalid password detected.  You can still proceed with an invalid password, but data will be decrypted to random garbage if the wrong password has been entered.  Proceed?'))
        return false;
      this.change_state('unlocked');
      break;
    case 'verified':
      this.change_state('unlocked');
      break;
    }
    return false;
  }

  handle_change_password_command() {
    this.change_state('change_password');
  }

  handle_edit_tab_command() {
    if(this.is_locked())
      return false;
    if(!this.is_text_tab_index(this.selected_tab_index))
      return false;
    const cleartext = this.cleartext_for_tab(this.selected_tab_index) ?? '';
    this.elt('cleartext_editor').value = cleartext;
    this.change_state('editing');
    this.elt('cleartext_editor').focus();
    return false;
  }

  handle_save_changes_command() {
    const new_cleartext = this.elt('cleartext_editor').value;
    const new_ciphertext = this.encrypt_text(new_cleartext) ?? '';
    this.set_ciphertext_for_tab(this.selected_tab_index, new_ciphertext);
    this.change_state('unlocked');
    return false;
  }

  handle_cancel_edit_tab_command() {
    this.elt('cleartext_editor').value = '';
    this.change_state('unlocked');
    return false;
  }

  // Forget the current password and wipe any cleartext on the page.
  handle_lock_command() {
    this.encryption_key = null;  // TODO: overwrite instead of just null out
    this.change_state('locked');
    return false;
  }

  handle_download_changes_command() {
    const document_string = this.full_document_as_string();
    const link_elt = document.createElement('a');
    const blob = new Blob([document_string], {type: 'text/html'});
    const object_url = URL.createObjectURL(blob);
    link_elt.setAttribute('href', URL.createObjectURL(blob));
    link_elt.setAttribute('download', this.generate_download_filename());
    document.body.appendChild(link_elt);
    link_elt.click();
    document.body.removeChild(link_elt);

    // TODO: need to clean up objectURL

    return false;
  }

  handle_copy_cleartext() {
    const cleartext = this.cleartext_for_tab(this.selected_tab_index) ?? '';
    if(cleartext.length > 0) {
      navigator.clipboard.writeText(cleartext);
      alert("Cleartext copied to system clipboard.");
    }
    return false;
  }

  // handle_copy_ciphertext() {
  //   const ciphertext = this.ciphertext_for_tab(this.selected_tab_index) ?? '';
  //   if(ciphertext.length > 0) {
  //     navigator.clipboard.writeText(ciphertext);
  //     alert("Ciphertext copied to system clipboard.");
  //   }
  //   return false;
  // }

  handle_upload_file() {
    const file_list = this.elt('file_upload').files;
    for(const file of [...file_list]) {
      // TODO: sanitize file names, check and warn for large files
      const reader = new FileReader();
      reader.onerror = () => { alert('Error reading ' + file.name); };
      reader.onload = (e) => {
        const filename = file.name;
        const size_limit = 500000;
        if(file.size > size_limit &&
           !window.confirm('You are uploading a large file (greater than 500kb).  This may result in poor performance or excess memory consumption.  Are you sure you want to continue?'))
          return;
        this.delete_file(filename);  // remove existing version if it exists
        this.create_file(filename, e.target.result);
        this.update_dom();
        this.update_tab_content();
      };
      reader.readAsArrayBuffer(file);
    }
    return false;
  }

  handle_download_file(filename) {
    let encrypted_file = this.find_file(filename);
    if(!encrypted_file) return false;

    const ciphertext = encrypted_file.encrypted_data();
    const plaintext = this.decrypt_data(ciphertext);

    const blob = new Blob([plaintext]);
    const anchor_elt = document.createElement('a');
    const file_url = URL.createObjectURL(blob);
    anchor_elt.href = file_url;
    anchor_elt.download = filename;
    document.body.appendChild(anchor_elt);
    anchor_elt.click();
    setTimeout(() => {
      document.body.removeChild(anchor_elt);
      URL.revokeObjectURL(file_url);
    }, 0);
    return false;
  }

  handle_delete_file(filename) {
    if(window.confirm("Really delete \"" + filename + "\"?")) {
      this.delete_file(filename);
      this.update_dom();
      this.update_tab_content();
    }
    return false;
  }

  delete_file(filename) {
    let encrypted_file = this.find_file(filename);
    if(encrypted_file)
      encrypted_file.parent_node.remove();
  }

  // Return the EncryptedFile for the given filename, if it exists.
  find_file(filename) {
    const encrypted_files = this.gather_encrypted_files();
    for(const encrypted_file of encrypted_files)
      if(encrypted_file.filename() === filename)
        return encrypted_file;
  }

  create_file(filename, array_buffer) {
    const bytearray = new Uint8Array(array_buffer);  // view buffer as bytes
    const encrypted_data = this.encrypt_data(bytearray);
    const date = new Date();
    const date_string = [
      date.getDate().toString().padStart(2, '0'),
      date.toLocaleString('default', {month: 'short'}),
      date.getFullYear().toString()
    ].join('-');  // 01-Jan-2026
    let file_node = this.create_elt('div', 'encrypted_file');
    file_node.appendChild(this.create_elt('div', 'filename', filename));
    file_node.appendChild(this.create_elt('div', 'filesize', array_buffer.byteLength));
    file_node.appendChild(this.create_elt('div', 'last_modified_date', date_string));
    file_node.appendChild(this.create_elt('div', 'encrypted_data', encrypted_data));
    this.elt('encrypted_files').appendChild(file_node);
    return file_node;
  }

  change_state(new_state) {
    this.state = new_state;
    this.update_dom();
    this.update_tab_content();
  }

  is_locked() {
    return !this.encryption_key;
  }

  // Set CSS classes, etc. according to the current app state
  update_dom() {
    // Highlight current tab label.
    for(const [tab_index, tab_node]
        of [...this.elt('tab_bar').children].entries())
      this.add_or_remove_class(
        tab_node, 'current',
        tab_index === this.selected_tab_index);
    // Hide/show tab content elements depending on state.
    const is_locked = this.is_locked();
    this.show_or_hide_elt('lock_command', !is_locked);
    this.show_or_hide_elt('locked_area', is_locked);
    this.show_or_hide_elt('unlocked_area', !is_locked);
    this.show_or_hide_elt('set_password_dialog', this.state === 'set_initial_password');
    this.show_or_hide_elt('decrypt_dialog', this.state === 'locked');
    this.show_or_hide_elt('change_password_command', !is_locked);
    this.show_or_hide_elt('change_password_dialog', this.state === 'change_password');
    this.show_or_hide_elt('cleartext_editor_container', this.state === 'editing');
    this.show_or_hide_elt('viewing_cleartext_commands', !(is_locked || this.state === 'editing' || this.state === 'change_password'));
    this.show_or_hide_elt('cleartext_tab_content', this.is_text_tab_index(this.selected_tab_index) && this.state !== 'editing');
    const any_files = this.gather_encrypted_files().length > 0;  // TODO: optimize
    this.show_or_hide_elt('files_tab_content', this.is_files_tab_index(this.selected_tab_index));
    this.show_or_hide_elt('file_list_is_empty', this.is_files_tab_index(this.selected_tab_index) && !any_files);
    this.show_or_hide_elt('files_table', this.is_files_tab_index(this.selected_tab_index) && any_files);

    if(this.state === 'set_initial_password')
      this.elt('set_password_input').focus();
    if(this.state === 'locked')
      this.elt('password_input').focus();
  }

  update_tab_content() {
    // Files tab is rendered specially.
    if(this.is_files_tab_index(this.selected_tab_index))
      return this.update_files_tab_content();
    // Otherwise, update the content for a textual tab.
    const cleartext_node = this.elt('cleartext_content');
    let cleartext_is_empty = false;
    if(this.state === 'unlocked' &&
       this.is_text_tab_index(this.selected_tab_index)) {
      const cleartext = this.cleartext_for_tab(this.selected_tab_index) ?? '';
      if(cleartext.length === 0)
        cleartext_is_empty = true;
      cleartext_node.innerText = cleartext;
    }
    this.add_or_remove_class(
      this.elt('cleartext_is_empty_message'),
      'hidden', !cleartext_is_empty);
  }

  update_files_tab_content() {
    const encrypted_files = this.gather_encrypted_files();
    let tbody_node = this.elt('files_table_body');
    tbody_node.textContent = '';  // delete existing rows
    for(const encrypted_file of encrypted_files) {
      const row_node = this.build_file_table_row(encrypted_file);
      tbody_node.appendChild(row_node);
    }
  }

  build_file_table_row(encrypted_file) {
    let row_node = this.create_elt('tr');
    row_node.appendChild(
      this.create_elt('td', 'filename', encrypted_file.filename()));
    row_node.appendChild(
      this.create_elt('td', 'filesize', encrypted_file.formatted_filesize()));
    row_node.appendChild(
      this.create_elt('td', 'last_modified_date', encrypted_file.last_modified_date_string()));
    let actions_node = this.create_elt('td', 'file_actions');

    // File actions:
    let command_node = null;
    command_node = this.create_elt('a', null, 'Download');
    command_node.href = '#';
    command_node.onclick = (() => {
      return this.handle_download_file(encrypted_file.filename());
    }).bind(this);
    actions_node.appendChild(command_node);
    command_node = this.create_elt('a', null, 'Delete');
    command_node.href = '#';
    command_node.onclick = (() => {
      return this.handle_delete_file(encrypted_file.filename());
    }).bind(this);
    actions_node.appendChild(command_node);
    
    row_node.appendChild(actions_node);
    return row_node;
  }

  node_for_tab_index(tab_index) {
    const node_name = ['tab', tab_index.toString(), 'ciphertext'].join('_');
    return this.elt(node_name);
  }

  ciphertext_for_tab(tab_index) {
    const node = this.node_for_tab_index(tab_index);
    if(!node) return null;
    const ciphertext = node.innerText ?? '';
    return ciphertext.length === 0 ? null : ciphertext;
  }

  set_ciphertext_for_tab(tab_index, new_ciphertext) {
    const node = this.node_for_tab_index(tab_index);
    if(!node) return null;
    node.innerText = new_ciphertext;
  }

  cleartext_for_tab(tab_index) {
    const ciphertext = this.ciphertext_for_tab(tab_index);
    if(ciphertext && this.encryption_key)
      return this.decrypt_text(ciphertext);
    else
      return null;
  }

  elt(element_id) {
    return document.getElementById(element_id);
  }

  create_elt(node_type, css_class = null, text_content = null) {
    let node = document.createElement(node_type);
    if(css_class) node.className = css_class;
    if(text_content) node.textContent = text_content;
    return node;
  }

  add_or_remove_class(node, class_name, add) {
    if(add)
      node.classList.add(class_name);
    else node.classList.remove(class_name);
  }

  show_or_hide_elt(element_id, show) {
    this.add_or_remove_class(this.elt(element_id), 'hidden', !show);
  }

  // Return complete HTML document string.
  full_document_as_string() {
    const doctype = document.doctype ?
          new XMLSerializer().serializeToString(document.doctype) : '';
    return doctype + document.documentElement.outerHTML;
  }

  generate_download_filename() {
    const date = new Date();
    return [
      'ajbcrypt', '_',
      date.getDate().toString().padStart(2, '0'), '_',
      date.toLocaleString('default', {month: 'short'}).toLowerCase(), '_',
      date.getFullYear().toString(),
      '.html'
    ].join('');
  }

  password_verification_phrase() { return 'Password is valid.'; }

  verify_password() {
    if(!this.encryption_key)
      return 'no_password';  // (potential) encryption key not entered yet by user.
    const verification_ciphertext = this.elt('verification_ciphertext').innerText ?? '';
    if(verification_ciphertext.length === 0) {
      // If there is no verification ciphertext in the document,
      // we can still try to use the key, it'll just decrypt text to garbage
      // if it's the wrong password.  This shouldn't normally happen unless
      // the user deletes the verification ciphertext from the document manually.
      return 'unverified';
    }
    // Try to decrypt the verification ciphertext embedded in the document
    // (from when the original encryption key was set) and make sure it decrypts
    // to what we expect.
    const verified =
          (this.decrypt_text(verification_ciphertext) ?? '') ===
          this.password_verification_phrase();
    return verified ? 'verified' : 'verification_failed';
  }

  update_password_verification_ciphertext() {
    const ciphertext = this.encrypt_text(this.password_verification_phrase());
    this.elt('verification_ciphertext').textContent = ciphertext;
  }

  has_password_verification_ciphertext() {
    return (this.elt('verification_ciphertext').textContent ?? '').length > 0;
  }

  // Based on JavaScrypt's jscrypt.js setKey().
  set_password(password) {
    let s = encode_utf8(password);
    let kmd5e, kmd5o;
    if(s.length === 1)
      s += s;
    md5_init();
    for(let i = 0; i < s.length; i += 2)
      md5_update(s.charCodeAt(i));
    md5_finish();
    kmd5e = byteArrayToHex(md5_digestBits);
    md5_init();
    for(let i = 0; i < s.length; i += 2)
      md5_update(s.charCodeAt(i));
    md5_finish();
    kmd5o = byteArrayToHex(md5_digestBits);
    const hs = kmd5e + kmd5o;
    this.encryption_key = hexToByteArray(hs);
  }

  change_password(new_password) {
    const old_encryption_key = this.encryption_key;
    this.set_password(new_password);
    const new_encryption_key = this.encryption_key;

    // TODO: don't hardcode 3
    for(let tab_index = 0; tab_index < 3; tab_index++) {
      this.encryption_key = old_encryption_key;
      const cleartext = this.cleartext_for_tab(tab_index);
      this.encryption_key = new_encryption_key;
      const ciphertext = this.encrypt_text(cleartext);
      this.set_ciphertext_for_tab(tab_index, ciphertext);
    }
    for(const encrypted_file of this.gather_encrypted_files()) {
      this.encryption_key = old_encryption_key;
      const cleartext = this.decrypt_data(encrypted_file.encrypted_data());
      this.encryption_key = new_encryption_key;
      const ciphertext = this.encrypt_data(cleartext);
      encrypted_file.set_encrypted_data(ciphertext);
    }
    this.update_password_verification_ciphertext();
  }

  gather_encrypted_files() {
    let encrypted_files = [];
    const root_node = this.elt('encrypted_files');
    const file_property_names = ['filename', 'filesize', 'last_modified_date', 'encrypted_data'];
    for(const node of [...root_node.childNodes]) {
      if(node.classList && node.classList.contains('encrypted_file')) {
        const property_nodes = {};
        for(const property_node of [...node.childNodes])
          for(const property_name of file_property_names)
            if(property_node.classList && property_node.classList.contains(property_name))
              property_nodes[property_name] = property_node;
        encrypted_files.push(new EncryptedFile(node, property_nodes));
      }
    }
    encrypted_files.sort((a, b) => {
      const a_fname = a.filename(), b_fname = b.filename();
      return a_fname === b_fname ? 0 :
        a_fname < b_fname ? -1 : +1;
    });
    return encrypted_files;
  }

  // Take a "plaintext" Uint8Array of data to encrypt, attach a header containing a
  // md5 checksum and length field, and pad it to the required block size.
  pack_plaintext_data(bytearray) {
    const bytes_per_block = Math.floor(blockSizeInBits/8);
    const plaintext_byte_length = bytearray.byteLength;
    const header_length = 20;
    const padding_length = bytes_per_block - ((plaintext_byte_length + header_length) % bytes_per_block);
    const packed_byte_length = plaintext_byte_length + header_length + padding_length;
    const message_data = new Uint8Array(new ArrayBuffer(packed_byte_length));
    // Calculate plaintext checksum.
    md5_init();
    for(let i = 0; i < plaintext_byte_length; i++)
      md5_update(bytearray[i]);
    md5_finish();
    // Write checksum into first 16 bytes of message buffer.
    for(let i = 0; i < md5_digestBits.length; i++)
      message_data[i] = md5_digestBits[i];
    // Write 32-bit data length into next 4 bytes of message buffer.
    message_data[16 + 0] = (plaintext_byte_length >>> 24) & 0xFF;
    message_data[16 + 1] = (plaintext_byte_length >>> 16) & 0xFF;
    message_data[16 + 2] = (plaintext_byte_length >>> 8) & 0xFF;
    message_data[16 + 3] = plaintext_byte_length & 0xFF;
    // Copy the plaintext into the message buffer after the header.
    message_data.set(bytearray, header_length);
    // Pad out to the block length with random data.
    for(let i = 0; i < padding_length; i++)
      message_data[header_length + plaintext_byte_length + i] = prng.nextInt(255);
    return message_data;
  }

  encrypt_text(text) {
    // Convert from Javascript's internal UTF-16 encoding to a UTF-8 byte array.
    const utf8_array = new TextEncoder().encode(text);
    return this.encrypt_data(utf8_array);
  }

  encrypt_data(bytearray) {
    if(!this.encryption_key)
      return null;  // shouldn't happen
    if(bytearray.byteLength === 0)
      return null;
    const key = this.encryption_key;
    addEntropyTime();
    if(!prng) prng = new AESprng(keyFromEntropy());
    const packed_data = this.pack_plaintext_data(bytearray);
    const ciphertext = rijndaelEncrypt(packed_data, key, 'CBC');
    const base64_ciphertext = armour_base64(ciphertext);
    return base64_ciphertext;
  }

  // NOTE: ciphertext is a Base64-encoded string.
  decrypt_data(ciphertext) {
    if(!ciphertext) return null;
    if(!this.encryption_key) return null;
    const ct = disarm_base64(ciphertext);
    let result = rijndaelDecrypt(ct, this.encryption_key, 'CBC');
    const header = result.slice(0, 20);
    result = result.slice(20);
    let dl = (header[16] << 24) | (header[17] << 16) | (header[18] << 8) | header[19];
    if(dl < 0 || dl > result.length) {
      // alert("Message (length " + result.length + ") truncated.  " +
      //       dl + " characters expected.");
      dl = result.length;
      return null;
    }
    md5_init();
    let plaintext_pieces = [];
    for(let i = 0; i < dl; i++) {
      plaintext_pieces.push(String.fromCharCode(result[i]));
      md5_update(result[i]);
    }
    const plaintext = plaintext_pieces.join('');
    md5_finish();
    for(let i = 0; i < md5_digestBits.length; i++) {
      if(md5_digestBits[i] !== header[i]) {
        // alert("Message corrupted.  Checksum of decrypted message does not match.");
        return null;
      }
    }
    return plaintext;
  }

  // Returns null if message is corrupted and/or encryption key is invalid.
  decrypt_text(ciphertext) {
    const plaintext = this.decrypt_data(ciphertext);
    if(!plaintext) return null;
    return decode_utf8(plaintext);
  }

  // "Optimized" version of the JavaScrypt rijndaelEncrypt() routine.
  // The original routine has a O(n^2) problem because of its use of concat().
  rijndael_encrypt_v2(bytearray) {
    let expandedKey = keyExpansion(this.encryption_key);
    const bpb = Math.floor(blockSizeInBits / 8);
    let ciphertext_blocks = [];

    ciphertext_blocks.push(getRandomBytes(bpb));
    borked();
  }
}


class EncryptedFile {
  // parent_node is the <div class="encrypted_file"> container representing the file.
  // property_nodes is a table of {'filename': elt, ...} with the properties.
  constructor(parent_node, property_nodes) {
    this.parent_node = parent_node;
    this.property_nodes = property_nodes;
  }

  property_value(property_name) {
    const node = this.property_nodes[property_name];
    return node ? (node.textContent ?? '') : '';
  }

  filename() { return this.property_value('filename'); }

  formatted_filesize() {
    const filesize = parseInt(this.property_value('filesize'));
    if(isNaN(filesize)) return '???';
    const kb = Math.floor((filesize + 1023)/1024);
    return kb.toString() + 'k';
  }

  last_modified_date_string() { return this.property_value('last_modified_date'); }

  encrypted_data() { return this.property_value('encrypted_data'); }

  set_encrypted_data(new_base64_data) {
    this.property_nodes['encrypted_data'].textContent = new_base64_data;
  }
}


$A = new App();

window.addEventListener('load', (event) => {
  $A.setup();
});

                        


