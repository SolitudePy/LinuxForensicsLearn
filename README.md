## 🌐 GitHub Pages
Visit the live site: [https://solitudepy.github.io/LinuxForensicsLearn](https://solitudepy.github.io/LinuxForensicsLearn)

## 🐳 GitHub Container Registry (GHCR) Image
A Docker image is automatically built and published to GitHub Container Registry (GHCR) on every push to the `master` branch.

### Serving it yourself
By default, `docker-compose.yml` can use the published image from GHCR:
```
git clone git@github.com:SolitudePy/LinuxForensicsLearn.git
cd LinuxForensicsLearn
docker compose build
docker compose up -d
```
This will pull the image from GHCR if you do not build locally.

### Build Locally (Optional)
If you want to build the image yourself (for local development or custom changes), you can use the `build` option in your `docker-compose.yml`:

```
services:
  jekyll-forensics:
    build:
      context: .
      dockerfile: Dockerfile
    # ...other options...
```

If both `build` and `image` are specified, Compose will build the image locally and use it instead of pulling from GHCR.

---