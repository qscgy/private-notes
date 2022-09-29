import pickle
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, time

class PrivNotes:
  MAX_NOTE_LEN = 2048

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """

    self.kvs = {}
    if data is not None:
      # TODO check checksum
      self.kvs = pickle.loads(bytes.fromhex(data))
      h = hashes.Hash(hashes.SHA256())
      data = pickle.dumps(self.kvs)
      h.update(data)
      ck = h.finalize()
      if checksum and ck != checksum:
        raise ValueError('Checksum does not match data')
      
      self.salt = self.kvs['salt']
    else:
      self.salt = os.urandom(16)
      self.kvs['salt'] = self.salt
    
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, iterations = 2000000, backend=default_backend())
    self.key = kdf.derive(bytes(password, 'ascii'))
    self.aesgcm = AESGCM(self.key)
    self.hmac_key = self.key
    self.consistent = True

  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    h = hashes.Hash(hashes.SHA256())
    data = pickle.dumps(self.kvs)
    h.update(data)
    checksum = h.finalize()
    return data.hex(), checksum

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    h = hmac.HMAC(self.hmac_key, hashes.SHA256())
    h.update(bytes(title, 'ascii'))
    signature = h.finalize()
    if signature in self.kvs:
      ctext, nonce = self.kvs[signature]
      message = self.aesgcm.decrypt(nonce, ctext, signature)
      message = message.decode('ascii')
      return message.strip()
    return None

  def set(self, title, note):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """
    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')

    padding = b"\x20"*(self.MAX_NOTE_LEN-len(note))
    note_bytes = bytes(note, 'ascii') + padding

    nonce = time.time_ns().to_bytes(8, 'little')
    hf = Cipher(algorithms.AES(self.key[:128]), modes.ECB())
    enc = hf.encryptor()
    nonce = enc.update(nonce+(b"\x01"*8)) + enc.finalize()   # Put the time through a PRP so the timestamp isn't in cleartext
    
    h = hmac.HMAC(self.hmac_key, hashes.SHA256())
    h.update(bytes(title, 'ascii'))
    signature = h.finalize()

    ciphertext = self.aesgcm.encrypt(nonce, note_bytes, signature)
    self.kvs[signature] = (ciphertext, nonce)


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    h = hmac.HMAC(self.key, hashes.SHA256())
    h.update(bytes(title, 'ascii'))
    signature = h.finalize()
    if signature in self.kvs:
      del self.kvs[signature]
      return True

    return False
