import attr
from flask import Markup, escape

@attr.s
class Format:
    exts = attr.ib()
    mimetype = attr.ib()
    preview = attr.ib()
    icon = attr.ib()

def image_preview(file):
    if file.size < (5*1024*1024): # 5MB
        return Markup('<img class="file_preview_img" src="{}">'.format(escape(file.url)))
    return Markup('<p class="file_preview_warning">Image is too large, please view <a href="{}" target="_blank">raw</a>!</p>'.format(escape(file.url)))
def audio_preview(file):
    return Markup('<audio class="file_preview_audio" controls src="{}">'.format(escape(file.url)))
def video_preview(file):
    return Markup('<video class="file_preview_video" controls src="{}">'.format(escape(file.url)))
def text_preview(file):
    d = file.get_data()
    try:
        if len(d) < 5*1024: # 5kB
            return Markup('<pre class="file_preview_text">{}</pre>'.format(escape(d.decode())))
        return Markup(
            '<p class="file_preview_warning">Warning: the file has been truncated to 5kB</p><pre class="file_preview_text">{}</pre>'\
                .format(escape(d[:5*1024].decode(errors='replace'))))
    except UnicodeDecodeError:
        return Markup(
            '<p class="file_preview_warning">Warning: the file is not valid UTF-8, it has been decoded as iso-8895-1 and truncated to 5kB</p><pre class="file_preview_text">{}</pre>'\
                .format(escape(d[:5*1024].decode('latin-1',errors='replace'))))
def swf_preview(file):
    return Markup('<embed src="{}" class="file_preview_flash" type="application/x-shockwave-flash"></embed>'.format(escape(file.url)))
def pdf_preview(file):
    return Markup('<embed src="{}" class="file_preview_pdf" type="application/pdf"></embed>'.format(escape(file.url))) # could have been pdfjs but js is haram
def fallback_preview(file):
    return Markup('<p class="file_preview_warning">Warning: this file cannot be previewed.</p>')

formats = [
    Format(
        {'jpg', 'jpeg'},
        'image/jpeg',
        image_preview,
        'page_white_picture'
    ),
    Format(
        {'png'},
        'image/png',
        image_preview,
        'page_white_picture'
    ),
    Format(
        {'gif'},
        'image/gif',
        image_preview,
        'page_white_picture'
    ),
    Format(
        {'webp'},
        'image/webp',
        image_preview,
        'page_white_picture'
    ),
    Format(
        {'mp3'},
        'audio/mpeg',
        audio_preview,
        'page_white_cd'
    ),
    Format(
        {'ogg'},
        'audio/ogg',
        audio_preview,
        'page_white_cd'
    ),
    Format(
        {'opus'},
        'audio/opus',
        audio_preview,
        'page_white_cd'
    ),
    Format(
        {'m4a'},
        'audio/x-m4a',
        audio_preview,
        'page_white_cd'
    ),
    Format(
        {'mp4'},
        'video/mp4',
        video_preview,
        'page_white_dvd'
    ),
    Format(
        {'webm', 'mkv'}, # yeah mkv, so what, makes it work usually
        'video/webm',
        video_preview,
        'page_white_dvd'
    ),
    Format(
        {'mov'},
        'video/quicktime',
        video_preview,
        'page_white_dvd'
    ),
    Format(
        {'txt'},
        'text/plain',
        text_preview,
        'page_white_text'
    ),
    Format(
        {'html', 'js', 'css', 'py', 'json', 'xml', 'c', 'h'},
        'text/plain',
        text_preview, # todo: code_preview?
        'page_white_code'
    ),
    Format(
        {'swf'},
        'application/x-shockwave-flash',
        swf_preview,
        'page_white_flash'
    ),
    Format(
        {'zip', '7z', 'rar', 'gz', 'tar'},
        'application/octet-stream', # download
        fallback_preview,
        'page_white_zip'
    ),
    Format(
        {'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'odt', 'odp', 'ods'},
        'application/octet-stream',
        fallback_preview,
        'page_white_office'
    ),
    Format(
        {'pdf'},
        'application/pdf',
        pdf_preview,
        'page_white_acrobat'
    ),
]
fallback = Format(
    set(),
    'application/octet-stream',
    fallback_preview,
    'page_white'
)

def pick_format(filename):
    ext = filename.split('.')[-1]
    for f in formats:
        if ext in f.exts:
            return f
    return fallback