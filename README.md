**note: this is unfinished because I got bored, the only thing that works is the basic hosting**

<p align="middle">
<img src="/.github/assets/banner.png" width="75%"">
</p>

# Paged - GitHub Pages Server & Basic Auth

It's a GitHub pages compatible server that allows for http basic authentication as well.

## How It Works

1. User pushes code to git
1. Your CI Solution:tm: packages the code into a zip file
1. Your CI Solution:tm: sends the ZIP file to the paged:tm::registered: server
1. The paged:tm::registered: server stores the files on disk
1. When a user requests a file, the paged server will check if the hostname the user requested corresponds to a site. If it does, it returns it. Otherwise, it returns a 404.
