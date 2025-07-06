---
title: FTP
description: FTP Handler
weight: 10
---

{{% alert title="In development feature" %}}
This feature is in development. Please help make it awesome by providing feedback on your experience using it.
{{% /alert %}}

## Purpose

Speak FTP to other computers you may or may not control. Currently only list files, but I'd like to support uploads for exfil purposes.

## Configuration

| Key           | Values                                |
|---------------|---------------------------------------|
| handler       | Must be `FTP`                         |
| listener      | Default `:21`                         |
| server_name   | Default `FTP Server`                  |
| fake_dir_tree | Default `test/old/fake,test/new/fake` |

## Additional Information

Things are still being created, documented, and fine-tuned.
