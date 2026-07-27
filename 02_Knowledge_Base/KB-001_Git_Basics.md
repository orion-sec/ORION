# Day 4 Git Commands

## Verify installations

```powershell
git --version
python --version
pwd
```

## Initialize Git

```powershell
git init
```

## Check repository status

```powershell
git status
```

## Configure Git

```powershell
git config --global user.name "Your Name"

git config --global user.email "email@example.com"
```

## Stage files

```powershell
git add .
```

## Commit

```powershell
git commit -m "Initial ORION project structure"
```

## Rename branch

```powershell
git branch -M main
```

## Connect to GitHub

```powershell
git remote add origin https://github.com/orion-sec/ORION.git
```

## Push

```powershell
git push -u origin main
```

### Navigate into Scripts folder
```powershell
cd 07_Scripts
```

### Run a Python script
```powershell
python ioc_extractor.py
```

### Push changes to GitHub
```powershell
git add .
git commit -m "Day 4 - IOC Extractor V1"
git push
```