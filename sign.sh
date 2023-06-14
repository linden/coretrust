codesign -s "Linden Developer ID" -f --entitlements ./source/spawner.entitlements source/spawner
codesign -s "Linden Developer ID" -f --entitlements ./source/main.entitlements source/main
