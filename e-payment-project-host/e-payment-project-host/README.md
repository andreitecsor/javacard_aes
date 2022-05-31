HOW TO TEST:
1. Import jars from YOUR_JAVACARD_PATH/lib (probably we only need *tools.jar*)
2. Terminal `cref_tdual -o memory.eeprom` -> creates memory
3. Terminal `apdutool`
    copy paste in terminal `e-payment-project/cap-e-payment-project.script`
    copy paste hw-create.script `hw-create.script`
4. Terminal `cref_tdual -i memory.eeprom` -> starts simulator
5. Run Main
   