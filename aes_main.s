.include "constants.s"

//CADENAS DE TEXTO
.section .data
    msg_txt: .asciz "Ingrese el texto a cifrar (maximo 16 caracteres): "
        lenMsgTxt = . - msg_txt

    msg_key: .asciz "Ingrese la clave (32 caracteres hex): "
        lenMsgKey = . - msg_key

    key_err_msg: .asciz "Error: Valor de clave incorrecto\n"
        lenKeyErr = . - key_err_msg

    newline: .asciz "\n"
    
    debug_state: .asciz "Matriz de Estado:\n"
        lenDebugState = . - debug_state
    
    debug_key: .asciz "Matriz de Clave:\n"
        lenDebugKey = . - debug_key
    
    msg_round: .asciz "\n=== RONDA "
        lenMsgRound = . - msg_round
    
    msg_round_end: .asciz " ===\n"
        lenMsgRoundEnd = . - msg_round_end
    
    msg_final: .asciz "\n=== CRIPTOGRAMA FINAL ===\n"
        lenMsgFinal = . - msg_final
    
    msg_after_subbytes: .asciz "Despues de SubBytes:\n"
        lenMsgAfterSub = . - msg_after_subbytes
    
    msg_after_shiftrows: .asciz "Despues de ShiftRows:\n"
        lenMsgAfterShift = . - msg_after_shiftrows
    
    msg_after_mixcolumns: .asciz "Despues de MixColumns:\n"
        lenMsgAfterMix = . - msg_after_mixcolumns
    
    msg_after_addroundkey: .asciz "Despues de AddRoundKey:\n"
        lenMsgAfterAdd = . - msg_after_addroundkey

// RESERVACION DE MEMORIA 
.section .bss
    .global matState
    matState: .space 16, 0

    .global key
    key: .space 16, 0

    .global expandedKey
    expandedKey: .space 176, 0      // 11 subclaves de 16 bytes = 176 bytes

    .global criptograma
    criptograma: .space 16, 0

    buffer: .space 256, 0
    
    tempColumn: .space 4, 0         // Temporal para MixColumns

// MACROS 
.macro print fd, buffer, len
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #64
    svc #0
.endm

.macro read fd, buffer, len
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #63
    svc #0
.endm

// CODIGO 
.section .text

/*
 * FUNCIÓN: readTextInput
 * Lee el texto a cifrar y lo almacena en matState en COLUMN-MAJOR ORDER
 */
.type readTextInput, %function
.global readTextInput
readTextInput:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    read 0, buffer, 256
    
    ldr x1, =buffer
    ldr x2, =matState
    mov x3, #0
    
convert_text_loop:
    cmp x3, #16
    b.ge pad_remaining_bytes
    
    ldrb w4, [x1, x3]
    cmp w4, #10
    b.eq pad_remaining_bytes
    cmp w4, #0
    b.eq pad_remaining_bytes
    
    // Column-major: index = (col * 4) + row
    // donde: col = index / 4, row = index % 4
    mov x7, #4
    udiv x8, x3, x7           // x8 = col = index / 4
    msub x9, x8, x7, x3       // x9 = row = index % 4
    
    // offset = row + (col * 4) = row + col * 4
    mul x10, x8, x7           // col * 4
    add x10, x10, x9          // + row
    
    strb w4, [x2, x10]
    add x3, x3, #1
    b convert_text_loop
    
pad_remaining_bytes:
    cmp x3, #16
    b.ge convert_text_done
    
    mov x7, #4
    udiv x8, x3, x7
    msub x9, x8, x7, x3
    mul x10, x8, x7
    add x10, x10, x9
    
    mov w4, #0
    strb w4, [x2, x10]
    add x3, x3, #1
    b pad_remaining_bytes
    
convert_text_done:
    ldp x29, x30, [sp], #16
    ret
    .size readTextInput, (. - readTextInput)

/*
 * FUNCIÓN: convertHexKey
 * Convierte la clave hexadecimal ingresada a bytes en COLUMN-MAJOR ORDER
 */
.type convertHexKey, %function
.global convertHexKey
convertHexKey:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    read 0, buffer, 33
    
    ldr x1, =buffer
    ldr x2, =key
    mov x3, #0
    mov x11, #0
    
convert_hex_loop:
    cmp x3, #16
    b.ge convert_hex_done
    
skip_non_hex:
    ldrb w4, [x1, x11]
    cmp w4, #0
    b.eq convert_hex_done
    cmp w4, #10
    b.eq convert_hex_done
    
    bl is_hex_char
    cmp w0, #1
    b.eq process_hex_pair
    
    add x11, x11, #1
    b skip_non_hex
    
process_hex_pair:
    ldrb w4, [x1, x11]
    add x11, x11, #1
    bl hex_char_to_nibble
    lsl w5, w0, #4
    
    ldrb w4, [x1, x11]
    add x11, x11, #1
    bl hex_char_to_nibble
    orr w5, w5, w0
    
    // Column-major: offset = row + (col * 4)
    mov x7, #4
    udiv x8, x3, x7           // col = index / 4
    msub x9, x8, x7, x3       // row = index % 4
    mul x10, x8, x7           // col * 4
    add x10, x10, x9          // + row
    
    strb w5, [x2, x10]
    add x3, x3, #1
    b convert_hex_loop
    
convert_hex_done:
    ldp x29, x30, [sp], #16
    ret
    .size convertHexKey, (. - convertHexKey)

/*
 * FUNCIONES AUXILIARES PARA CONVERSION HEX
 */
is_hex_char:
    cmp w4, #'0'
    b.lt not_hex
    cmp w4, #'9'
    b.le is_hex
    
    orr w4, w4, #0x20
    cmp w4, #'a'
    b.lt not_hex
    cmp w4, #'f'
    b.le is_hex
    
not_hex:
    mov w0, #0
    ret
is_hex:
    mov w0, #1
    ret

hex_char_to_nibble:
    cmp w4, #'0'
    b.lt hex_error
    cmp w4, #'9'
    b.le hex_digit
    
    orr w4, w4, #0x20
    cmp w4, #'a'
    b.lt hex_error
    cmp w4, #'f'
    b.gt hex_error
    
    sub w0, w4, #'a'
    add w0, w0, #10
    ret
    
hex_digit:
    sub w0, w4, #'0'
    ret
    
hex_error:
    print 1, key_err_msg, lenKeyErr
    mov w0, #0
    ret

/*
 * FUNCIÓN: printMatrix
 * Imprime una matriz 4x4 en formato hexadecimal (column-major storage)
 */
.type printMatrix, %function
.global printMatrix
printMatrix:
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    
    str x0, [sp, #16]
    str x1, [sp, #24]
    str x2, [sp, #32]
    
    mov x0, #1
    ldr x1, [sp, #24]
    ldr x2, [sp, #32]
    mov x8, #64
    svc #0
    
    mov x23, #0               // contador de filas
    
print_row_loop:
    cmp x23, #4
    b.ge print_matrix_done
    
    mov x24, #0               // contador de columnas
    
print_col_loop:
    cmp x24, #4
    b.ge print_row_newline
    
    // Column-major: índice = row + (col * 4)
    mov x25, #4
    mul x25, x24, x25         // col * 4
    add x25, x25, x23         // + row
    
    ldr x20, [sp, #16]
    ldrb w0, [x20, x25]
    bl print_hex_byte
    
    add x24, x24, #1
    b print_col_loop
    
print_row_newline:
    print 1, newline, 1
    add x23, x23, #1
    b print_row_loop
    
print_matrix_done:
    print 1, newline, 1
    ldp x29, x30, [sp], #48
    ret
    .size printMatrix, (. - printMatrix)

/*
 * FUNCIÓN: print_hex_byte
 * Imprime un byte en formato hexadecimal
 */
print_hex_byte:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    
    and w1, w0, #0xF0
    lsr w1, w1, #4
    and w2, w0, #0x0F
    
    cmp w1, #10
    b.lt high_digit
    add w1, w1, #'A' - 10
    b high_done
high_digit:
    add w1, w1, #'0'
high_done:
    
    cmp w2, #10
    b.lt low_digit
    add w2, w2, #'A' - 10
    b low_done
low_digit:
    add w2, w2, #'0'
low_done:
    
    sub sp, sp, #16
    strb w1, [sp]
    strb w2, [sp, #1]
    mov w3, #' '
    strb w3, [sp, #2]
    
    mov x0, #1
    mov x1, sp
    mov x2, #3
    mov x8, #64
    svc #0
    
    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ret

/*
 * FUNCIÓN: addRoundKey
 * Realiza XOR entre matState y una subclave
 * Entrada: x0 = número de ronda (0-10)
 */
.type addRoundKey, %function
.global addRoundKey
addRoundKey:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    
    str x19, [sp, #16]
    str x20, [sp, #24]
    
    // Calcular offset de la subclave: ronda * 16
    lsl x1, x0, #4              // x1 = ronda * 16
    
    ldr x19, =matState
    ldr x20, =expandedKey
    add x20, x20, x1            // x20 apunta a la subclave de esta ronda
    
    mov x2, #0
    
addroundkey_loop:
    cmp x2, #16
    b.ge addroundkey_done
    
    ldrb w3, [x19, x2]
    ldrb w4, [x20, x2]
    eor w5, w3, w4
    strb w5, [x19, x2]
    
    add x2, x2, #1
    b addroundkey_loop
    
addroundkey_done:
    ldr x19, [sp, #16]
    ldr x20, [sp, #24]
    
    ldp x29, x30, [sp], #32
    ret
    .size addRoundKey, (. - addRoundKey)

/*
 * FUNCIÓN: subBytes
 * Sustituye cada byte de matState usando la S-box
 */
.type subBytes, %function
.global subBytes
subBytes:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    
    str x19, [sp, #16]
    str x20, [sp, #24]
    
    ldr x19, =matState
    ldr x20, =Sbox
    
    mov x0, #0
    
subbytes_loop:
    cmp x0, #16
    b.ge subbytes_done
    
    ldrb w1, [x19, x0]
    uxtw x1, w1
    ldrb w2, [x20, x1]
    strb w2, [x19, x0]
    
    add x0, x0, #1
    b subbytes_loop
    
subbytes_done:
    ldr x19, [sp, #16]
    ldr x20, [sp, #24]
    
    ldp x29, x30, [sp], #32
    ret
    .size subBytes, (. - subBytes)

/*
 * FUNCIÓN: shiftRows
 * Rota las filas de matState:
 * Fila 0: no rota
 * Fila 1: rota 1 posición a la izquierda
 * Fila 2: rota 2 posiciones a la izquierda
 * Fila 3: rota 3 posiciones a la izquierda
 */
.type shiftRows, %function
.global shiftRows
shiftRows:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    
    str x19, [sp, #16]
    
    ldr x19, =matState
    
    // Fila 0: no se rota
    
    // Fila 1: rotar 1 posición (índices 1,5,9,13)
    ldrb w0, [x19, #1]   // temp = [1]
    ldrb w1, [x19, #5]
    strb w1, [x19, #1]   // [1] = [5]
    ldrb w1, [x19, #9]
    strb w1, [x19, #5]   // [5] = [9]
    ldrb w1, [x19, #13]
    strb w1, [x19, #9]   // [9] = [13]
    strb w0, [x19, #13]  // [13] = temp
    
    // Fila 2: rotar 2 posiciones (índices 2,6,10,14)
    ldrb w0, [x19, #2]   // temp1 = [2]
    ldrb w1, [x19, #6]   // temp2 = [6]
    ldrb w2, [x19, #10]
    strb w2, [x19, #2]   // [2] = [10]
    ldrb w2, [x19, #14]
    strb w2, [x19, #6]   // [6] = [14]
    strb w0, [x19, #10]  // [10] = temp1
    strb w1, [x19, #14]  // [14] = temp2
    
    // Fila 3: rotar 3 posiciones (índices 3,7,11,15)
    ldrb w0, [x19, #3]   // temp = [3]
    ldrb w1, [x19, #15]
    strb w1, [x19, #3]   // [3] = [15]
    ldrb w1, [x19, #11]
    strb w1, [x19, #15]  // [15] = [11]
    ldrb w1, [x19, #7]
    strb w1, [x19, #11]  // [11] = [7]
    strb w0, [x19, #7]   // [7] = temp
    
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
    .size shiftRows, (. - shiftRows)

/*
 * FUNCIÓN: galoisMult
 * Multiplicación en campo de Galois GF(2^8)
 * Entrada: w0 = a, w1 = b
 * Salida: w0 = a * b en GF(2^8)
 */
.type galoisMult, %function
galoisMult:
    mov w2, #0              // resultado
    mov w3, w0              // copia de a
    mov w4, #8              // contador
    
galois_loop:
    cbz w4, galois_done
    
    // Si el bit menos significativo de b es 1, XOR con a
    tst w1, #1
    b.eq galois_skip_xor
    eor w2, w2, w3
    
galois_skip_xor:
    // Verificar si a tiene bit alto en 1
    mov w5, #0x80
    tst w3, w5
    lsl w3, w3, #1          // a = a << 1
    b.eq galois_no_reduce
    mov w5, #0x1b
    eor w3, w3, w5          // Reducir con polinomio irreducible
    
galois_no_reduce:
    lsr w1, w1, #1          // b = b >> 1
    sub w4, w4, #1
    b galois_loop
    
galois_done:
    and w0, w2, #0xFF
    ret
    .size galoisMult, (. - galoisMult)

// xtime: w0 = (w0 << 1) ^ (0x1B si el bit7 anterior era 1)
.type xtime, %function
.global xtime
xtime:
    and     w1, w0, #0x80       // guarda si el bit7 estaba encendido
    lsl     w0, w0, #1          // x << 1
    cbz     w1, 1f              // si no estaba encendido, no reducimos
    mov     w2, #0x1B           // <<<< cargar inmediato en registro
    eor     w0, w0, w2          // reducción con 0x1B
1:  and     w0, w0, #0xFF       // limitar a 8 bits
    ret


// MixColumns para 1 columna (usa xtime). ¡Ahora preserva x19–x22!
.type mixColumns, %function
.global mixColumns
mixColumns:
    // Prólogo: guardar FP/LR y callee-saved
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]   // por si acaso (no estrictamente necesario)

    ldr x19, =matState
    mov x20, #0                 // col = 0..3

MC_loop:
    cmp x20, #4
    b.ge MC_done

    lsl x21, x20, #2            // base = col*4
    add x22, x19, x21

    ldrb w4, [x22, #0]          // a0
    ldrb w5, [x22, #1]          // a1
    ldrb w6, [x22, #2]          // a2
    ldrb w7, [x22, #3]          // a3

    // t = a0 ^ a1 ^ a2 ^ a3
    eor  w8,  w4, w5
    eor  w8,  w8, w6
    eor  w8,  w8, w7

    // u = a0 (valor original)
    mov  w9,  w4

    // a0 = a0 ^ t ^ xtime(a0 ^ a1)
    eor  w0,  w4, w5
    bl   xtime
    eor  w0,  w0, w8
    eor  w4,  w4, w0

    // a1 = a1 ^ t ^ xtime(a1 ^ a2)
    eor  w0,  w5, w6
    bl   xtime
    eor  w0,  w0, w8
    eor  w5,  w5, w0

    // a2 = a2 ^ t ^ xtime(a2 ^ a3)
    eor  w0,  w6, w7
    bl   xtime
    eor  w0,  w0, w8
    eor  w6,  w6, w0

    // a3 = a3 ^ t ^ xtime(a3 ^ u)
    eor  w0,  w7, w9
    bl   xtime
    eor  w0,  w0, w8
    eor  w7,  w7, w0

    // guardar columna
    strb w4, [x22, #0]
    strb w5, [x22, #1]
    strb w6, [x22, #2]
    strb w7, [x22, #3]

    add  x20, x20, #1
    b    MC_loop

MC_done:
    // Epílogo: restaurar callee-saved y FP/LR
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret




/*
 * FUNCIÓN: rotWord
 * Rota una palabra de 4 bytes: [a0,a1,a2,a3] -> [a1,a2,a3,a0]
 * Entrada: x0 = dirección de la palabra
 */
.type rotWord, %function
rotWord:
    ldrb w1, [x0, #0]
    ldrb w2, [x0, #1]
    ldrb w3, [x0, #2]
    ldrb w4, [x0, #3]
    
    strb w2, [x0, #0]
    strb w3, [x0, #1]
    strb w4, [x0, #2]
    strb w1, [x0, #3]
    
    ret
    .size rotWord, (. - rotWord)

/*
 * FUNCIÓN: subWord
 * Aplica S-box a cada byte de una palabra
 * Entrada: x0 = dirección de la palabra
 */
.type subWord, %function
subWord:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    
    str x19, [sp, #16]
    str x20, [sp, #24]
    
    mov x19, x0
    ldr x20, =Sbox
    
    mov x1, #0
subword_loop:
    cmp x1, #4
    b.ge subword_done
    
    ldrb w2, [x19, x1]
    uxtw x2, w2
    ldrb w3, [x20, x2]
    strb w3, [x19, x1]
    
    add x1, x1, #1
    b subword_loop
    
subword_done:
    ldr x19, [sp, #16]
    ldr x20, [sp, #24]
    
    ldp x29, x30, [sp], #32
    ret
    .size subWord, (. - subWord)

/*
 * FUNCIÓN: keyExpansion
 * Expande la clave inicial a 11 subclaves (176 bytes)
 */
.type keyExpansion, %function
.global keyExpansion
keyExpansion:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    
    str x19, [sp, #16]
    str x20, [sp, #24]
    str x21, [sp, #32]
    str x22, [sp, #40]
    str x23, [sp, #48]
    
    ldr x19, =key
    ldr x20, =expandedKey
    ldr x21, =Rcon
    
    // Copiar clave inicial a expandedKey
    mov x0, #0
copy_initial_key:
    cmp x0, #16
    b.ge expand_keys
    
    ldrb w1, [x19, x0]
    strb w1, [x20, x0]
    
    add x0, x0, #1
    b copy_initial_key
    
expand_keys:
    mov x22, #4             // i = 4 (palabra actual)
    
expand_loop:
    cmp x22, #44            // 44 palabras = 11 subclaves
    b.ge expand_done
    
    // Calcular dirección de W[i-1]
    sub x0, x22, #1
    lsl x0, x0, #2
    add x23, x20, x0        // x23 = &expandedKey[(i-1)*4]
    
    // Copiar W[i-1] al stack como temporal
    ldrb w1, [x23, #0]
    ldrb w2, [x23, #1]
    ldrb w3, [x23, #2]
    ldrb w4, [x23, #3]
    strb w1, [sp, #52]
    strb w2, [sp, #53]
    strb w3, [sp, #54]
    strb w4, [sp, #55]
    
    // Si i es múltiplo de 4
    mov x1, #4
    udiv x2, x22, x1
    msub x3, x2, x1, x22
    cbnz x3, expand_not_multiple
    
    // RotWord
    add x0, sp, #52
    bl rotWord
    
    // SubWord
    add x0, sp, #52
    bl subWord
    
    // XOR con Rcon[i/4 - 1]
    udiv x0, x22, x1
    sub x0, x0, #1
    lsl x0, x0, #2
    add x0, x21, x0
    
    ldrb w1, [sp, #52]
    ldrb w2, [x0, #0]
    eor w1, w1, w2
    strb w1, [sp, #52]
    
expand_not_multiple:
    // W[i] = W[i-4] XOR temp
    sub x0, x22, #4
    lsl x0, x0, #2
    add x0, x20, x0         // x0 = &expandedKey[(i-4)*4]
    
    lsl x1, x22, #2
    add x1, x20, x1         // x1 = &expandedKey[i*4]
    
    ldrb w2, [x0, #0]
    ldrb w3, [sp, #52]
    eor w2, w2, w3
    strb w2, [x1, #0]
    
    ldrb w2, [x0, #1]
    ldrb w3, [sp, #53]
    eor w2, w2, w3
    strb w2, [x1, #1]
    
    ldrb w2, [x0, #2]
    ldrb w3, [sp, #54]
    eor w2, w2, w3
    strb w2, [x1, #2]
    
    ldrb w2, [x0, #3]
    ldrb w3, [sp, #55]
    eor w2, w2, w3
    strb w2, [x1, #3]
    
    add x22, x22, #1
    b expand_loop
    
expand_done:
    ldr x19, [sp, #16]
    ldr x20, [sp, #24]
    ldr x21, [sp, #32]
    ldr x22, [sp, #40]
    ldr x23, [sp, #48]
    
    ldp x29, x30, [sp], #64
    ret
    .size keyExpansion, (. - keyExpansion)

/*
 * FUNCIÓN: print_round_number
 * Imprime el número de ronda
 * Entrada: w0 = número de ronda
 */
.type print_round_number, %function
print_round_number:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    
    // Guardar número de ronda
    sub sp, sp, #16
    str w0, [sp, #12]
    
    // Imprimir "=== RONDA "
    print 1, msg_round, lenMsgRound
    
    // Convertir número a ASCII (manejar 1-9 y 10)
    ldr w0, [sp, #12]
    cmp w0, #10
    b.lt single_digit
    
    // Es 10: imprimir "10"
    mov w1, #'1'
    strb w1, [sp]
    mov w1, #'0'
    strb w1, [sp, #1]
    
    mov x0, #1
    mov x1, sp
    mov x2, #2
    mov x8, #64
    svc #0
    b print_round_end
    
single_digit:
    // Es 1-9: convertir a ASCII
    add w0, w0, #'0'
    strb w0, [sp]
    
    mov x0, #1
    mov x1, sp
    mov x2, #1
    mov x8, #64
    svc #0
    
print_round_end:
    // Imprimir " ===\n"
    print 1, msg_round_end, lenMsgRoundEnd
    
    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ret
    .size print_round_number, (. - print_round_number)

/*
 * FUNCIÓN: aes_encrypt
 * Realiza el cifrado AES-128 completo (10 rondas)
 */
.type aes_encrypt, %function
.global aes_encrypt
aes_encrypt:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    
    str x19, [sp, #16]
    
    // Ronda inicial: AddRoundKey con la primera subclave
    mov x0, #0
    bl addRoundKey
    
    // 9 rondas principales (1 a 9)
    mov x19, #1
    
main_rounds_loop:
    cmp x19, #10
    b.ge final_round
    
    // Imprimir número de ronda
    mov w0, w19
    bl print_round_number
    
    // SubBytes
    bl subBytes
    print 1, msg_after_subbytes, lenMsgAfterSub
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    // ShiftRows
    bl shiftRows
    print 1, msg_after_shiftrows, lenMsgAfterShift
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    // MixColumns
    bl mixColumns
    print 1, msg_after_mixcolumns, lenMsgAfterMix
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    // AddRoundKey
    mov x0, x19
    bl addRoundKey
    print 1, msg_after_addroundkey, lenMsgAfterAdd
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    add x19, x19, #1
    b main_rounds_loop
    
final_round:
    // Ronda final (10): Sin MixColumns
    mov w0, #10
    bl print_round_number
    
    // SubBytes
    bl subBytes
    print 1, msg_after_subbytes, lenMsgAfterSub
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    // ShiftRows
    bl shiftRows
    print 1, msg_after_shiftrows, lenMsgAfterShift
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    // AddRoundKey con la última subclave
    mov x0, #10
    bl addRoundKey
    
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
    .size aes_encrypt, (. - aes_encrypt)

/*
 * FUNCIÓN: _start
 * Función principal del programa
 */
.type _start, %function
.global _start
_start:
    // Leer texto a cifrar
    print 1, msg_txt, lenMsgTxt
    bl readTextInput
    
    // Mostrar estado inicial
    print 1, debug_state, lenDebugState
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    // Leer clave
    print 1, msg_key, lenMsgKey
    bl convertHexKey
    
    // Mostrar clave
    print 1, debug_key, lenDebugKey
    ldr x0, =key
    ldr x1, =debug_key
    mov x2, lenDebugKey
    bl printMatrix
    
    // Expandir clave
    bl keyExpansion
    
    // Realizar cifrado AES-128 completo
    bl aes_encrypt
    
    // Mostrar criptograma final
    print 1, msg_final, lenMsgFinal
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    // Salir del programa
    mov x0, #0
    mov x8, #93
    svc #0
    
    .size _start, (. - _start)