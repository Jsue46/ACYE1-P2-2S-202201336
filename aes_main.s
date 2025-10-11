.include "constants.s"          // Incluye constantes (Sbox, Rcon, etc.) y cualquier dato auxiliar definido aparte

// =========================
// SECCIÓN DE DATOS (.data)
// =========================
.section .data
    // Mensajes y longitudes para I/O (se imprimen con write)
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

    msg_cipher_text: .asciz "Texto cifrado: "
        lenMsgCipherText = . - msg_cipher_text
    
    msg_time: .asciz "\nTiempo de ejecucion: "
        lenMsgTime = . - msg_time
    
    msg_ms: .asciz " ms\n"
        lenMsgMs = . - msg_ms

menu_msg: .asciz "\n=== MENU AES-128 ===\n1) Ingresar TEXTO (ASCII)\n2) Ingresar CLAVE (32 HEX)\n3) Ejecutar AES-128\n4) Informacion\n5) Salir\n> "
    lenMenu = . - menu_msg

info_msg: .asciz "\nAES-128: 10 rondas; bloque 16 bytes; clave 16 bytes.\nVector NIST:\nKey: 000102030405060708090A0B0C0D0E0F\nPT : 00112233445566778899AABBCCDDEEFF\nCT : 69C4E0D86A7B0430D8CDB78070B4C55A\n"
    lenInfo = . - info_msg

need_txt_msg: .asciz "Primero ingrese el TEXTO.\n"
    lenNeedTxt = . - need_txt_msg

need_key_msg: .asciz "Primero ingrese la CLAVE.\n"
    lenNeedKey = . - need_key_msg

run_msg:  .asciz "\nEjecutando AES-128...\n"
    lenRun = . - run_msg
done_msg: .asciz "Listo.\n"
    lenDone = . - done_msg

    msg_cipher_text_ascii: .asciz "Texto cifrado (ASCII): "
    lenMsgCipherTextAscii = . - msg_cipher_text_ascii

    msg_cipher_text_hex:   .asciz "Texto cifrado (HEX): "
        lenMsgCipherHex = . - msg_cipher_text_hex

    rk_prefix: .asciz "Subclave Ronda "
    lenRkPrefix = . - rk_prefix


// ==========================
// SECCIÓN BSS (.bss) - RAM
// ==========================
.section .bss
    .balign 1
    .global has_text, has_keyf
    has_text:  .space 1, 0      // Flag: se ingresó texto (1) o no (0)
    has_keyf:  .space 1, 0      // Flag: se ingresó clave válida (1) o no (0)

    .global matState
    matState: .space 16, 0      // Matriz de estado 4x4 bytes (storage en column-major)

    .global key
    key: .space 16, 0           // Clave de 128 bits (en column-major)

    .global expandedKey
    expandedKey: .space 176, 0  // 11 subclaves × 16 bytes = 176 bytes

    .global criptograma
    criptograma: .space 16, 0   // Buffer opcional para salida final (no indispensable)

    buffer: .space 256, 0       // Buffer general de entrada/salida
    
    tempColumn: .space 4, 0     // Temporal por columna para MixColumns

    // Tiempos (struct timespec: tv_sec (8B) + tv_nsec (8B))
    start_time: .space 16, 0
    end_time:   .space 16, 0


// ================================
// MACROS DE SISTEMA (read/write)
// ================================
.macro print fd, buffer, len
    // write(fd, buffer, len)
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #64              // syscall write
    svc #0
.endm

.macro read fd, buffer, len
    // read(fd, buffer, len)
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #63              // syscall read
    svc #0
.endm


// ======================
// SECCIÓN DE CÓDIGO
// ======================
.section .text

/*
 * FUNCIÓN: readTextInput
 * Objetivo: Leer hasta 16 bytes de texto (stdin) y guardarlos en matState en orden column-major.
 * Entrada: usa 'buffer' como destino de read; copia a matState; rellena con 0 si hay menos de 16.
 * Convención: guarda/l restaura x29/x30 (prólogo/epílogo).
 */
.type readTextInput, %function
.global readTextInput
readTextInput:
    stp x29, x30, [sp, #-16]!   // Prólogo: salvar FP y LR
    mov x29, sp

    read 0, buffer, 256         // Lee una línea (hasta 256 bytes)

    ldr x1, =buffer             // x1 -> origen (ASCII)
    ldr x2, =matState           // x2 -> destino (matriz estado)
    mov x3, #0                  // x3 = índice de byte leído (0..15)
    
convert_text_loop:
    cmp x3, #16                 // Si ya copiamos 16, pasar a padding
    b.ge pad_remaining_bytes
    
    ldrb w4, [x1, x3]           // w4 = byte leído
    cmp w4, #10                 // detener si '\n'
    b.eq pad_remaining_bytes
    cmp w4, #0                  // detener si fin de cadena
    b.eq pad_remaining_bytes
    
    // Mapeo a column-major:
    // index lógico = x3
    // col = index / 4, row = index % 4
    mov x7, #4
    udiv x8, x3, x7             // x8 = col
    msub x9, x8, x7, x3         // x9 = row
    mul x10, x8, x7             // col*4
    add x10, x10, x9            // offset = row + col*4
    
    strb w4, [x2, x10]          // Guarda byte en matState[offset]
    add x3, x3, #1
    b convert_text_loop
    
pad_remaining_bytes:
    // Rellena con 0 los bytes restantes (padding simple)
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
    ldp x29, x30, [sp], #16     // Epílogo: restaurar FP y LR
    ret
    .size readTextInput, (. - readTextInput)


/*
 * FUNCIÓN: convertHexKey
 * Objetivo: Leer cadena HEX de clave (stdin) y convertir a 16 bytes en 'key' (column-major).
 * Detalles: filtra caracteres no-hex, agrupa nibbles de dos en dos; valida que salgan 16 bytes.
 * Retorno: w0 = 1 (OK) / 0 (clave inválida).
 */
.type convertHexKey, %function
.global convertHexKey
convertHexKey:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    read 0, buffer, 33          // Lee hasta 32 hex + '\n'

    ldr x1, =buffer             // x1 -> origen
    ldr x2, =key                // x2 -> destino
    mov x3, #0                  // x3 = bytes válidos generados (0..16)
    mov x11, #0                 // x11 = cursor en buffer
    
convert_hex_loop:
    cmp x3, #16                 // Ya tenemos 16 bytes?
    b.ge validate_len
    
skip_non_hex:
    ldrb w4, [x1, x11]          // w4 = char actual
    cmp w4, #0                  // fin de cadena?
    b.eq validate_len
    cmp w4, #10                 // '\n'?
    b.eq validate_len

    bl is_hex_char              // ¿Es hex?
    cmp w0, #1
    b.ne inc_cursor

    // Toma nibble alto
    ldrb w4, [x1, x11]
    add x11, x11, #1
    bl hex_char_to_nibble
    cmp w0, #0xFF               // 0xFF => error
    b.eq bad_key
    lsl w5, w0, #4              // w5 = nibble alto << 4

    // Toma nibble bajo
    ldrb w4, [x1, x11]
    add x11, x11, #1
    bl hex_char_to_nibble
    cmp w0, #0xFF
    b.eq bad_key
    orr w5, w5, w0              // w5 = byte completo

    // Escribe en 'key' en column-major: offset = row + col*4
    mov x7, #4
    udiv x8, x3, x7             // col = x3/4
    msub x9, x8, x7, x3         // row = x3%4
    mul x10, x8, x7
    add x10, x10, x9
    strb w5, [x2, x10]

    add x3, x3, #1
    b convert_hex_loop

inc_cursor:
    add x11, x11, #1            // Avanza hasta encontrar siguiente posible hex
    b skip_non_hex

validate_len:
    cmp x3, #16                 // Deben ser exactamente 16 bytes
    b.eq good_key
bad_key:
    print 1, key_err_msg, lenKeyErr
    mov w0, #0
    b convert_hex_done

good_key:
    mov w0, #1                  // OK
    
convert_hex_done:
    ldp x29, x30, [sp], #16
    ret
    .size convertHexKey, (. - convertHexKey)


/*
 * AUXILIARES PARA CONVERSIÓN HEX
 * is_hex_char: retorna 1 si w4 es [0-9a-fA-F], si no 0.
 * hex_char_to_nibble: convierte w4 a nibble (0..15) o 0xFF si inválido.
 */
is_hex_char:
    cmp w4, #'0'
    b.lt not_hex
    cmp w4, #'9'
    b.le is_hex
    
    orr w4, w4, #0x20           // Normaliza a minúscula
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
    // 0..9
    cmp w4, #'0'
    b.lt nibble_err
    cmp w4, #'9'
    b.le is_digit
    // A..F / a..f
    orr w4, w4, #0x20
    cmp w4, #'a'
    b.lt nibble_err
    cmp w4, #'f'
    b.gt nibble_err
    sub w0, w4, #'a'
    add w0, w0, #10
    ret
is_digit:
    sub w0, w4, #'0'
    ret
nibble_err:
    mov w0, #0xFF
    ret

    
hex_digit:
    // Devuelve nibble numérico (no usado directamente en el flujo principal)
    sub w0, w4, #'0'
    ret
    
hex_error:
    // Imprime error y retorna 0 (no usado cuando se usa convertHexKey)
    print 1, key_err_msg, lenKeyErr
    mov w0, #0
    ret


/*
 * FUNCIÓN: printMatrix
 * Objetivo: Imprimir matriz 4x4 (matriz en column-major) en HEX, fila por fila.
 * Parámetros:
 *   x0 = puntero a matriz (16B)
 *   x1 = puntero a título (string)
 *   x2 = longitud del título
 */
.type printMatrix, %function
.global printMatrix
printMatrix:
    // Prólogo: reservar y salvar registros que se usan
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    str x25, [sp, #64]

    // Guardar parámetros en stack (para reuso)
    str x0, [sp, #72]     // matriz
    str x1, [sp, #80]     // título
    str x2, [sp, #88]     // len título

    // Imprime título
    mov x0, #1
    ldr x1, [sp, #80]
    ldr x2, [sp, #88]
    mov x8, #64
    svc #0

    // Recorre filas (row = 0..3) y columnas (col = 0..3)
    mov x23, #0
1:  cmp x23, #4
    b.ge 3f
    mov x24, #0
2:  cmp x24, #4
    b.ge 4f

    // Calcula offset column-major: offset = row + col*4
    mov x25, #4
    mul x25, x24, x25
    add x25, x25, x23

    ldr x20, [sp, #72]          // x20 -> matriz
    ldrb w0, [x20, x25]         // w0 = byte a imprimir
    bl print_hex_byte           // Imprime en HEX con espacio

    add x24, x24, #1
    b 2b

4:  print 1, newline, 1         // Nueva línea por cada fila
    add x23, x23, #1
    b 1b

3:  print 1, newline, 1         // Línea en blanco al final

    // Epílogo: restaurar registros
    ldr x25, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret


/*
 * FUNCIÓN: print_hex_byte
 * Objetivo: Imprimir un byte (w0) en HEX (2 chars) seguido de espacio.
 * Usa write(1, sp, 3).
 */
print_hex_byte:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    
    // Separar nibble alto y bajo
    and w1, w0, #0xF0
    lsr w1, w1, #4
    and w2, w0, #0x0F
    
    // Convertir nibble alto a ASCII
    cmp w1, #10
    b.lt high_digit
    add w1, w1, #'A' - 10
    b high_done
high_digit:
    add w1, w1, #'0'
high_done:
    // Convertir nibble bajo a ASCII
    cmp w2, #10
    b.lt low_digit
    add w2, w2, #'A' - 10
    b low_done
low_digit:
    add w2, w2, #'0'
low_done:
    
    // Armar buffer "XY "
    sub sp, sp, #16
    strb w1, [sp]
    strb w2, [sp, #1]
    mov  w3, #' '
    strb w3, [sp, #2]
    
    // write(1, sp, 3)
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
 * Objetivo: XOR entre matState y subclave de la ronda indicada.
 * Parámetro: x0 = número de ronda (0..10)
 */
.type addRoundKey, %function
.global addRoundKey
addRoundKey:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    str x20, [sp, #24]
    
    // x1 = offset subclave = ronda * 16
    lsl x1, x0, #4

    ldr x19, =matState
    ldr x20, =expandedKey
    add x20, x20, x1            // x20 -> inicio subclave de la ronda
    
    mov x2, #0                  // contador de bytes 0..15
addroundkey_loop:
    cmp x2, #16
    b.ge addroundkey_done
    
    ldrb w3, [x19, x2]          // estado
    ldrb w4, [x20, x2]          // subclave
    eor  w5, w3, w4             // XOR
    strb w5, [x19, x2]          // guarda en estado
    
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
 * Objetivo: Sustituir cada byte de matState por Sbox[byte].
 */
.type subBytes, %function
.global subBytes
subBytes:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    str x20, [sp, #24]
    
    ldr x19, =matState
    ldr x20, =Sbox             // Tabla de sustitución
    
    mov x0, #0                 // índice 0..15
subbytes_loop:
    cmp x0, #16
    b.ge subbytes_done
    
    ldrb w1, [x19, x0]         // byte actual
    uxtw x1, w1                // x1 = índice a Sbox
    ldrb w2, [x20, x1]         // Sbox[byte]
    strb w2, [x19, x0]         // escribe
    
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
 * Objetivo: Rotar filas de matState en column-major:
 *   Fila0 sin cambio; Fila1 rota 1; Fila2 rota 2; Fila3 rota 3 posiciones a izquierda.
 * Índices de fila en column-major:
 *   F1: [1,5,9,13]  F2: [2,6,10,14]  F3: [3,7,11,15]
 */
.type shiftRows, %function
.global shiftRows
shiftRows:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    
    ldr x19, =matState
    
    // Fila 0: sin cambio
    
    // Fila 1: rotación de 1 a la izquierda: [1,5,9,13] -> [5,9,13,1]
    ldrb w0, [x19, #1]   // temp = [1]
    ldrb w1, [x19, #5]
    strb w1, [x19, #1]   // [1] = [5]
    ldrb w1, [x19, #9]
    strb w1, [x19, #5]   // [5] = [9]
    ldrb w1, [x19, #13]
    strb w1, [x19, #9]   // [9] = [13]
    strb w0, [x19, #13]  // [13] = temp
    
    // Fila 2: rotación de 2 a la izquierda: [2,6,10,14] -> [10,14,2,6]
    ldrb w0, [x19, #2]   // temp1 = [2]
    ldrb w1, [x19, #6]   // temp2 = [6]
    ldrb w2, [x19, #10]
    strb w2, [x19, #2]   // [2]  = [10]
    ldrb w2, [x19, #14]
    strb w2, [x19, #6]   // [6]  = [14]
    strb w0, [x19, #10]  // [10] = temp1
    strb w1, [x19, #14]  // [14] = temp2
    
    // Fila 3: rotación de 3 a la izquierda: [3,7,11,15] -> [15,3,7,11]
    ldrb w0, [x19, #3]   // temp = [3]
    ldrb w1, [x19, #15]
    strb w1, [x19, #3]   // [3]  = [15]
    ldrb w1, [x19, #11]
    strb w1, [x19, #15]  // [15] = [11]
    ldrb w1, [x19, #7]
    strb w1, [x19, #11]  // [11] = [7]
    strb w0, [x19, #7]   // [7]  = temp
    
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
    .size shiftRows, (. - shiftRows)


/*
 * FUNCIÓN: galoisMult
 * Objetivo: Multiplicación a*b en GF(2^8) con polinomio irreducible 0x11B.
 * Entradas: w0=a, w1=b; Salida: w0=resultado.
 */
.type galoisMult, %function
galoisMult:
    mov w2, #0              // w2 = acumulador (resultado)
    mov w3, w0              // w3 = a (mutable)
    mov w4, #8              // 8 iteraciones (por cada bit de b)
galois_loop:
    cbz w4, galois_done
    
    // Si LSB(b) = 1, XOR acumulador con a
    tst w1, #1
    b.eq galois_skip_xor
    eor w2, w2, w3
    
galois_skip_xor:
    // Desplaza a y reduce si el bit alto estaba en 1
    mov w5, #0x80
    tst w3, w5
    lsl w3, w3, #1
    b.eq galois_no_reduce
    mov w5, #0x1b
    eor w3, w3, w5          // reducción módulo x^8 + x^4 + x^3 + x + 1
    
galois_no_reduce:
    lsr w1, w1, #1          // Avanza siguiente bit de b
    sub w4, w4, #1
    b galois_loop
    
galois_done:
    and w0, w2, #0xFF       // Limita a 8 bits
    ret
    .size galoisMult, (. - galoisMult)


// FUNCIÓN: xtime
// Objetivo: xtime(x) = (x << 1) ^ 0x1B si bit7 estaba en 1 (reducción AES).
.type xtime, %function
.global xtime
xtime:
    and     w1, w0, #0x80   // w1 = bit7 previo
    lsl     w0, w0, #1      // x << 1
    cbz     w1, 1f          // si bit7==0 no se reduce
    mov     w2, #0x1B
    eor     w0, w0, w2      // reducción
1:  and     w0, w0, #0xFF   // limitar a 8 bits
    ret


/*
 * FUNCIÓN: mixColumns
 * Objetivo: Mezclar cada columna de matState según matriz constante de AES.
 * Implementación: usa la forma optimizada con t = a0^a1^a2^a3 y xtime sobre pares.
 */
.type mixColumns, %function
.global mixColumns
mixColumns:
    // Prólogo: guarda FP/LR y callee-saved usados
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    ldr x19, =matState
    mov x20, #0                 // col = 0..3

MC_loop:
    cmp x20, #4
    b.ge MC_done

    // Base de la columna: x22 = &matState[col*4]
    lsl x21, x20, #2
    add x22, x19, x21

    // Cargar a0..a3
    ldrb w4, [x22, #0]
    ldrb w5, [x22, #1]
    ldrb w6, [x22, #2]
    ldrb w7, [x22, #3]

    // t = a0 ^ a1 ^ a2 ^ a3
    eor  w8,  w4, w5
    eor  w8,  w8, w6
    eor  w8,  w8, w7

    // u = a0 (copia original)
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

    // Guardar columna actualizada
    strb w4, [x22, #0]
    strb w5, [x22, #1]
    strb w6, [x22, #2]
    strb w7, [x22, #3]

    add  x20, x20, #1
    b    MC_loop

MC_done:
    // Epílogo
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret


/*
 * FUNCIÓN: rotWord
 * Objetivo: Rotar una palabra de 4B a la izquierda: [a0,a1,a2,a3] -> [a1,a2,a3,a0]
 * Parámetro: x0 = puntero a palabra (4 bytes)
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
 * Objetivo: Aplicar Sbox a cada byte de una palabra de 4B.
 * Parámetro: x0 = puntero a palabra (4 bytes)
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
 * Objetivo: Expandir 'key' (16B) a 11 subclaves en 'expandedKey' (176B).
 * Reglas AES-128: 44 palabras (4B), i=0..43; cada 4 palabras se aplica RotWord, SubWord y Rcon.
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
    
    // Copia la clave base (16B) en expandedKey[0..15]
    mov x0, #0
copy_initial_key:
    cmp x0, #16
    b.ge expand_keys
    
    ldrb w1, [x19, x0]
    strb w1, [x20, x0]
    add x0, x0, #1
    b copy_initial_key
    
expand_keys:
    mov x22, #4                 // i = 4 (palabra actual, de 0 a 43)
    
expand_loop:
    cmp x22, #44
    b.ge expand_done
    
    // x23 = &W[i-1]
    sub x0, x22, #1
    lsl x0, x0, #2
    add x23, x20, x0
    
    // Copiar W[i-1] a temporales en stack
    ldrb w1, [x23, #0]
    ldrb w2, [x23, #1]
    ldrb w3, [x23, #2]
    ldrb w4, [x23, #3]
    strb w1, [sp, #52]
    strb w2, [sp, #53]
    strb w3, [sp, #54]
    strb w4, [sp, #55]
    
    // Si i%4 == 0, aplicar RotWord, SubWord y XOR con Rcon[(i/4)-1]
    mov x1, #4
    udiv x2, x22, x1
    msub x3, x2, x1, x22        // x3 = i % 4
    cbnz x3, expand_not_multiple
    
    // RotWord(temp)
    add x0, sp, #52
    bl rotWord
    
    // SubWord(temp)
    add x0, sp, #52
    bl subWord
    
    // Rcon[(i/4)-1]
    udiv x0, x22, x1
    sub x0, x0, #1
    lsl x0, x0, #2
    add x0, x21, x0
    
    ldrb w1, [sp, #52]
    ldrb w2, [x0, #0]
    eor  w1, w1, w2
    strb w1, [sp, #52]
    
expand_not_multiple:
    // W[i] = W[i-4] XOR temp
    sub x0, x22, #4
    lsl x0, x0, #2
    add x0, x20, x0             // &W[i-4]
    
    lsl x1, x22, #2
    add x1, x20, x1             // &W[i]
    
    ldrb w2, [x0, #0]
    ldrb w3, [sp, #52]
    eor  w2, w2, w3
    strb w2, [x1, #0]
    
    ldrb w2, [x0, #1]
    ldrb w3, [sp, #53]
    eor  w2, w2, w3
    strb w2, [x1, #1]
    
    ldrb w2, [x0, #2]
    ldrb w3, [sp, #54]
    eor  w2, w2, w3
    strb w2, [x1, #2]
    
    ldrb w2, [x0, #3]
    ldrb w3, [sp, #55]
    eor  w2, w2, w3
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
 * Objetivo: Imprimir "=== RONDA NN ===" para NN en [1..10] o 0.
 * Parámetro: w0 = número de ronda
 */
.type print_round_number, %function
print_round_number:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    
    // Guarda el número de ronda en stack
    sub sp, sp, #16
    str w0, [sp, #12]
    
    // Imprime prefijo
    print 1, msg_round, lenMsgRound
    
    // Convierte el número (1 dígito o "10")
    ldr w0, [sp, #12]
    cmp w0, #10
    b.lt single_digit
    
    // Es 10: imprime '1','0'
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
    add w0, w0, #'0'
    strb w0, [sp]
    mov x0, #1
    mov x1, sp
    mov x2, #1
    mov x8, #64
    svc #0
    
print_round_end:
    // Sufijo " ===\n"
    print 1, msg_round_end, lenMsgRoundEnd
    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ret
    .size print_round_number, (. - print_round_number)


/*
 * FUNCIÓN: printRoundKeys
 * Objetivo: Imprimir las 11 subclaves (rondas 0..10) como matrices 4x4.
 */
.type printRoundKeys, %function
.global printRoundKeys
printRoundKeys:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    mov x19, #0                  // ronda = 0..10
1:  cmp x19, #11
    b.ge 2f

    // Encabezado "Subclave Ronda N"
    print 1, rk_prefix, lenRkPrefix
    mov x0, x19
    bl print_number
    print 1, newline, 1

    // Selecciona subclave base y muestra con printMatrix
    ldr x20, =expandedKey
    lsl x0, x19, #4              // offset = ronda * 16
    add x0, x20, x0
    ldr x1, =debug_key
    mov x2, lenDebugKey
    bl printMatrix

    add x19, x19, #1
    b 1b
2:  ldp x29, x30, [sp], #32
    ret


/*
 * FUNCIÓN: aes_encrypt
 * Objetivo: Ejecutar AES-128 completo: ARK(0), 9 rondas [SB,SR,MC,ARK], ronda final [SB,SR,ARK].
 * Efecto: Resultado queda en matState.
 */
.type aes_encrypt, %function
.global aes_encrypt
aes_encrypt:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    
    // Ronda inicial: AddRoundKey con subclave 0
    mov x0, #0
    bl addRoundKey
    print 1, msg_after_addroundkey, lenMsgAfterAdd
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix

    // Rondas 1..9
    mov x19, #1
main_rounds_loop:
    cmp x19, #10
    b.ge final_round
    
    // Encabezado de ronda
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
    
    // AddRoundKey (subclave = número de ronda actual)
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
    // Ronda 10: sin MixColumns
    mov w0, #10
    bl print_round_number
    
    bl subBytes
    print 1, msg_after_subbytes, lenMsgAfterSub
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    bl shiftRows
    print 1, msg_after_shiftrows, lenMsgAfterShift
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    
    mov x0, #10
    bl addRoundKey              // ARK final
    
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
    .size aes_encrypt, (. - aes_encrypt)


/*
 * FUNCIÓN: get_time
 * Objetivo: Llamar a clock_gettime(CLOCK_MONOTONIC, &timespec).
 * Parámetro: x0 = &timespec destino.
 */
.type get_time, %function
get_time:
    mov x1, x0          // x1 = &timespec
    mov x0, #1          // CLOCK_MONOTONIC = 1
    mov x8, #113        // syscall clock_gettime
    svc #0
    ret


/*
 * FUNCIÓN: print_cipher_text
 * Objetivo: Imprimir matState completo en HEX continuo (32 chars) sin espacios.
 */
.type print_cipher_text, %function
print_cipher_text:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    print 1, msg_cipher_text_hex,   lenMsgCipherHex

    ldr x19, =matState
    mov x20, #0
print_cipher_loop:
    cmp x20, #16
    b.ge print_cipher_done
    ldrb w0, [x19, x20]
    bl print_hex_byte_no_space
    add x20, x20, #1
    b print_cipher_loop
    
print_cipher_done:
    print 1, newline, 1
    ldp x29, x30, [sp], #16
    ret
    .size print_cipher_text, (. - print_cipher_text)


/*
 * FUNCIÓN: print_hex_byte_no_space
 * Objetivo: Imprime un byte en HEX sin espacio (2 chars).
 * Entrada: w0 = byte.
 */
print_hex_byte_no_space:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    
    and w1, w0, #0xF0
    lsr w1, w1, #4
    and w2, w0, #0x0F
    
    cmp w1, #10
    b.lt high_digit_ns
    add w1, w1, #'A' - 10
    b high_done_ns
high_digit_ns:
    add w1, w1, #'0'
high_done_ns:
    cmp w2, #10
    b.lt low_digit_ns
    add w2, w2, #'A' - 10
    b low_done_ns
low_digit_ns:
    add w2, w2, #'0'
low_done_ns:
    
    sub sp, sp, #16
    strb w1, [sp]
    strb w2, [sp, #1]
    mov x0, #1
    mov x1, sp
    mov x2, #2
    mov x8, #64
    svc #0
    
    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ret


/*
 * FUNCIÓN: print_execution_time
 * Objetivo: Calcular Δt = end-start en microsegundos y mostrar en milisegundos con 3 decimales.
 * Usa start_time y end_time (timespec).
 */
.type print_execution_time, %function
print_execution_time:
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    str x19, [sp, #16]
    str x20, [sp, #24]
    str x21, [sp, #32]
    
    // Cargar timespec de inicio
    ldr x0, =start_time
    ldr x1, [x0]            // start_sec
    ldr x2, [x0, #8]        // start_nsec
    
    // Cargar timespec de fin
    ldr x0, =end_time
    ldr x3, [x0]            // end_sec
    ldr x4, [x0, #8]        // end_nsec
    
    // Δsec y Δnsec
    sub x5, x3, x1          // diff_sec
    sub x6, x4, x2          // diff_nsec
    
    // Normaliza si diff_nsec < 0
    cmp x6, #0
    b.ge time_calc
    mov x7, #1000
    mov x8, #1000
    mul x7, x7, x8
    mov x8, #1000
    mul x7, x7, x8          // x7 = 1,000,000,000
    add x6, x6, x7
    sub x5, x5, #1
    
time_calc:
    // total_us = diff_sec*1_000_000 + diff_nsec/1000
    mov x7, #1000
    mov x8, #1000
    mul x7, x7, x8          // x7 = 1,000,000
    mul x19, x5, x7         // sec -> us
    
    mov x7, #1000
    udiv x8, x6, x7         // nsec -> us
    add x19, x19, x8        // total_us
    
    // ms enteros y 3 decimales
    mov x7, #1000
    udiv x20, x19, x7       // parte entera (ms)
    msub x21, x20, x7, x19  // decimales (us restantes 0..999)
    
    // Imprime "Tiempo de ejecucion: "
    print 1, msg_time, lenMsgTime
    
    // Parte entera (ms)
    mov x0, x20
    bl print_number
    
    // Punto decimal
    sub sp, sp, #16
    mov w0, #'.'
    strb w0, [sp]
    mov x0, #1
    mov x1, sp
    mov x2, #1
    mov x8, #64
    svc #0
    add sp, sp, #16
    
    // Decimales con padding a 3 dígitos
    mov x0, x21
    bl print_number_3digits
    
    print 1, msg_ms, lenMsgMs
    
    ldr x19, [sp, #16]
    ldr x20, [sp, #24]
    ldr x21, [sp, #32]
    ldp x29, x30, [sp], #48
    ret
    .size print_execution_time, (. - print_execution_time)


/*
 * FUNCIÓN: print_number_3digits
 * Objetivo: Imprimir valor [0..999] con padding a 3 dígitos.
 * Parámetro: x0 = valor (0..999)
 */
.type print_number_3digits, %function
print_number_3digits:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    sub sp, sp, #16

    // centenas
    mov x1, #100
    udiv x2, x0, x1           // x2 = centenas
    msub x0, x2, x1, x0       // resto 0..99
    add w2, w2, #'0'
    strb w2, [sp]

    // decenas
    mov x1, #10
    udiv x3, x0, x1           // x3 = decenas
    msub x0, x3, x1, x0       // resto 0..9
    add w3, w3, #'0'
    strb w3, [sp, #1]

    // unidades
    add w0, w0, #'0'
    strb w0, [sp, #2]

    // write(1, sp, 3)
    mov x0, #1
    mov x1, sp
    mov x2, #3
    mov x8, #64
    svc #0

    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ret
    .size print_number_3digits, (. - print_number_3digits)


/*
 * FUNCIÓN: print_number
 * Objetivo: Imprimir número decimal sin signo (x0).
 * Parámetro: x0 = número a imprimir.
 */
.type print_number, %function
print_number:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    sub sp, sp, #32
    mov x1, sp
    add x1, x1, #31         // x1 apunta al final del buffer
    mov x2, #0              // contador de dígitos
    
    cbz x0, print_zero
convert_loop:
    cbz x0, print_digits
    mov x3, #10
    udiv x4, x0, x3         // x4 = x0 / 10
    msub x5, x4, x3, x0     // x5 = x0 % 10
    add x5, x5, #'0'        // ASCII
    strb w5, [x1]
    sub x1, x1, #1
    add x2, x2, #1
    mov x0, x4
    b convert_loop
    
print_zero:
    mov w3, #'0'
    strb w3, [x1]
    mov x2, #1
    b print_digits
    
print_digits:
    add x1, x1, #1         // x1 -> primer dígito
    mov x0, #1
    mov x8, #64
    svc #0
    
    add sp, sp, #32
    ldp x29, x30, [sp], #32
    ret
    .size print_number, (. - print_number)


/*
 * FUNCIÓN: print_cipher_text_ascii
 * Objetivo: Imprimir matState byte a byte como caracteres (ASCII directo).
 */
.type print_cipher_text_ascii, %function
print_cipher_text_ascii:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    str x20, [sp, #24]
    
    print 1, msg_cipher_text_ascii, lenMsgCipherTextAscii

    ldr x19, =matState
    sub sp, sp, #16
    mov x20, #0
    
print_ascii_loop:
    cmp x20, #16
    b.ge print_ascii_done
    
    ldrb w0, [x19, x20]     // Toma un byte del estado final
    strb w0, [sp]           // Colócalo en buffer temporal
    
    mov x0, #1              // write(1, sp, 1)
    mov x1, sp
    mov x2, #1
    mov x8, #64
    svc #0
    
    add x20, x20, #1
    b print_ascii_loop
    
print_ascii_done:
    add sp, sp, #16
    print 1, newline, 1
    
    ldr x19, [sp, #16]
    ldr x20, [sp, #24]
    ldp x29, x30, [sp], #32
    ret
    .size print_cipher_text_ascii, (. - print_cipher_text_ascii)


// =============================
// PUNTO DE ENTRADA (_start)
// =============================
.section .text
.type _start, %function
.global _start
_start:
    // Inicializa banderas de ingreso
    ldr x0, =has_text
    mov w1, #0
    strb w1, [x0]
    ldr x0, =has_keyf
    strb w1, [x0]

menu_loop:
    // Mostrar menú y leer opción
    print 1, menu_msg, lenMenu
    read  0, buffer, 16
    ldr   x0, =buffer
    ldrb  w0, [x0]            // primer carácter

    // Despachar según opción
    cmp w0, #'1'
    b.eq opt_text
    cmp w0, #'2'
    b.eq opt_key
    cmp w0, #'3'
    b.eq opt_run
    cmp w0, #'4'
    b.eq opt_info
    cmp w0, #'5'
    b.eq opt_exit
    b menu_loop               // opción inválida -> repetir

// 1) Ingresar TEXTO
opt_text:
    print 1, msg_txt, lenMsgTxt
    bl readTextInput
    ldr x1, =has_text
    mov w0, #1
    strb w0, [x1]

    // Mostrar estado actual para validación
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    b menu_loop

// 2) Ingresar CLAVE
opt_key:
    print 1, msg_key, lenMsgKey
    bl convertHexKey
    cbz w0, menu_loop              // si falla la clave, regresa al menú

    ldr x1, =has_keyf
    mov w0, #1
    strb w0, [x1]

    // Mostrar clave en matriz (column-major) para validación
    ldr x0, =key
    ldr x1, =debug_key
    mov x2, lenDebugKey
    bl printMatrix
    b menu_loop


// 3) Ejecutar AES-128 completo
opt_run:
    // Verifica que haya texto
    ldr x0, =has_text
    ldrb w0, [x0]
    cbz w0, faltatexto

    // Verifica que haya clave
    ldr x0, =has_keyf
    ldrb w0, [x0]
    cbz w0, faltaclave

    print 1, run_msg, lenRun

    // Marca tiempo de inicio
    ldr x0, =start_time
    bl get_time

    // Expansión de clave y cifrado
    bl keyExpansion
    bl printRoundKeys    
    bl aes_encrypt

    // Marca tiempo de fin
    ldr x0, =end_time
    bl get_time

    // Muestra matriz final y salidas requeridas
    print 1, msg_final, lenMsgFinal
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix

    // Imprime criptograma (HEX continuo) y también en ASCII
    bl print_cipher_text
    bl print_cipher_text_ascii
    bl print_execution_time

    print 1, done_msg, lenDone
    b menu_loop

faltatexto:
    print 1, need_txt_msg, lenNeedTxt
    b menu_loop
faltaclave:
    print 1, need_key_msg, lenNeedKey
    b menu_loop


// 4) Información del programa y vector de prueba NIST
opt_info:
    print 1, info_msg, lenInfo
    b menu_loop

// 5) Salida limpia del proceso
opt_exit:
    mov x0, #0
    mov x8, #93          // SYS_exit
    svc #0
