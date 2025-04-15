from PyPDF2 import PdfReader, PdfWriter

def encrypt_pdf(inputpath, outputpath, password):
    reader = PdfReader(inputpath)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(password)

    with open(outputpath, 'wb') as output_file:
        writer.write(output_file)

def decrypt_pdf(inputpath, outputpath, password):
    reader = PdfReader(inputpath)
    writer = PdfWriter()

    if reader.is_encrypted:
        reader.decrypt(password)

    for page in reader.pages:
        writer.add_page(page)
    
    with open(outputpath, 'wb') as output_file:
        writer.write(output_file)
    
# encrypt_pdf('./catcv.pdf', './catcv_encrypted.pdf','password')
decrypt_pdf('./catcv_encrypted.pdf','./catcv_decrypted.pdf', 'password')
