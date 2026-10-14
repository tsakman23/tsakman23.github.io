# tsakman23.github.io

My personal website hosted at: [tsakman23.github.io](https://tsakman23.github.io/)

This repository contains a Jekyll site. The recommended way to run and edit it is with VS Code Dev Containers for a consistent environment.

## Prerequisites

- [Visual Studio Code](https://code.visualstudio.com/)
- [Git](https://git-scm.com/)
- One of:
  - [Docker Desktop](https://www.docker.com/products/docker-desktop/)
  - Docker Engine
- VS Code extension: [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

## Recommended workflow (VS Code + Dev Container)

This repository already includes `.devcontainer/devcontainer.json`.

1. Clone the repository:

   ```bash
   git clone https://github.com/tsakman23/tsakman23.github.io.git
   cd tsakman23.github.io
   ```

2. Open the folder in VS Code.
3. Open the Command Palette (`Ctrl/Cmd+Shift+P`) and run **Dev Containers: Reopen in Container**.
4. Wait for container setup to finish.
5. Start the Jekyll server:

   ```bash
   bundle exec jekyll serve --livereload
   ```

6. Open <http://127.0.0.1:4000> in your browser.

Keep the terminal running while you edit files; Jekyll will rebuild and live reload changes.

## Alternative: run locally (without container)

If you prefer, you can run locally, but the container workflow above is recommended for consistency.

```bash
git clone https://github.com/tsakman23/tsakman23.github.io.git
cd tsakman23.github.io
bundle install
bundle exec jekyll serve --livereload
```

Then open <http://127.0.0.1:4000>.

## Editing and previewing changes

- Edit content in files such as `_posts/` (blog posts), `_tabs/` (tab pages), and other site pages.
- Save your changes and refresh the browser (or rely on live reload) to preview updates locally.

## Troubleshooting

- **Container startup issues:** Ensure Docker is running, then retry **Dev Containers: Reopen in Container**.
- **Dependency install errors:** Run `bundle install` in the project root and retry `bundle exec jekyll serve --livereload`.
- **Port conflicts on 4000:** Stop the other process using port 4000, or run Jekyll on another port, for example `bundle exec jekyll serve --livereload --port 4001`.
