module.exports = {
  '**/*.{js,jsx,ts,tsx}': [
    'jest --bail --watchAll=false --findRelatedTests --passWithNoTests',
    () => 'tsc-files --noEmit',
  ],
  '**/*.{ts,js,json,md}': ['prettier --write'],
}