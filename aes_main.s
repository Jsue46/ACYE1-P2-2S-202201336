.include "constants.s"

// =======================
//   CONSTANTES / MACROS
// =======================
.equ SYS_read,          63
.equ SYS_write,         64
.equ SYS_exit,          93
.equ SYS_clock_gettime, 113
.equ CLOCK_MONOTONIC,   1

.macro print fd, buffer, len
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #SYS_write
    svc #0
.endm

.macro read fd, buffer, len
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #SYS_read
    svc #0
.endm

.macro idx_from_linear dst, i
    mov     x7, #4
    udiv    x8, \i, x7
    msub    x9, x8, x7, \i
    mul     \dst, x9, x7
    add     \dst, \dst, x8
.endm

// =======================
//      DATA / BSS
// =======================
.section .data
    msg_txt: .asciz "Ingrese el texto a cifrar (maximo 16 caracteres ASCII): "
        lenMsgTxt = . - msg_txt
    msg_key: .asciz "Ingrese la clave (32 caracteres hex): "
        lenMsgKey = . - msg_key
    key_err_msg: .asciz "Error: clave HEX invalida (deben ser 32 hex exactos)\n"
        lenKeyErr = . - key_err_msg
    newline: .asciz "\n"

    dbg_after_ark0: .asciz "Despues de AddRoundKey (inicial):\n"
        len_dbg_after_ark0 = . - dbg_after_ark0
    dbg_after_sb:  .asciz "Despues de SubBytes:\n"
        len_dbg_after_sb = . - dbg_after_sb
    dbg_after_sr:  .asciz "Despues de ShiftRows:\n"
        len_dbg_after_sr = . - dbg_after_sr
    dbg_after_mc:  .asciz "Despues de MixColumns:\n"
        len_dbg_after_mc = . - dbg_after_mc
    dbg_after_ark: .asciz "Despues de AddRoundKey (ronda):\n"
        len_dbg_after_ark = . - dbg_after_ark
    dbg_final:     .asciz "Estado final (tras ronda 10):\n"
        len_dbg_final = . - dbg_final

    debug_state: .asciz "Matriz de Estado:\n"
        lenDebugState = . - debug_state
    debug_key: .asciz "Matriz de Clave/Subclave:\n"
        lenDebugKey = . - debug_key

    menu_msg: .asciz "\n=== MENU AES-128 ===\n1) Ingresar TEXTO (ASCII)\n2) Ingresar CLAVE (32 HEX)\n3) Ejecutar AES-128\n4) Informacion\n5) Salir\n> "
        lenMenu = . - menu_msg
    info_msg: .asciz "\nAES-128: 10 rondas; bloque 16 bytes; clave 16 bytes.\nVector NIST:\nKey: 000102030405060708090A0B0C0D0E0F\nPT : 00112233445566778899AABBCCDDEEFF\nCT : 69C4E0D86A7B0430D8CDB78070B4C55A\n"
        lenInfo = . - info_msg
    run_msg: .asciz "\nEjecutando AES-128...\n"
        lenRun = . - run_msg
    done_msg: .asciz "Listo.\n"
        lenDone = . - done_msg
    need_txt_msg: .asciz "Primero ingrese el TEXTO.\n"
        lenNeedTxt = . - need_txt_msg
    need_key_msg: .asciz "Primero ingrese la CLAVE.\n"
        lenNeedKey = . - need_key_msg
    cipher_msg: .asciz "Ciphertext (HEX): "
        lenCipher = . - cipher_msg
    tmsg: .asciz "Tiempo (ns): "
        lenT = . - tmsg

.section .bss
    .balign 16
    .global matState
    matState: .space 16, 0
    .global key
    key: .space 16, 0
    .global round_keys
    round_keys: .space 44*4, 0
    buffer: .space 256, 0
    has_text: .space 1, 0
    has_keyf: .space 1, 0
    debug_on: .space 1, 0

// =======================
//        I/O
// =======================
.section .text

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
    idx_from_linear x10, x3
    strb w4, [x2, x10]
    add x3, x3, #1
    b convert_text_loop
pad_remaining_bytes:
    cmp x3, #16
    b.ge convert_text_done
    idx_from_linear x10, x3
    mov w4, #0
    strb w4, [x2, x10]
    add x3, x3, #1
    b pad_remaining_bytes
convert_text_done:
    ldp x29, x30, [sp], #16
    ret

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
not_hex: mov w0, #0; ret
is_hex:  mov w0, #1; ret

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

.type convertHexKey, %function
.global convertHexKey
convertHexKey:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    read 0, buffer, 64
    ldr x1, =buffer
    ldr x2, =key
    mov x3, #0
    mov x11, #0
    mov x12, #0
    mov w6, #0
next_char:
    ldrb w4, [x1, x11]
    cmp w4, #0
    b.eq end_hex
    cmp w4, #10
    b.eq end_hex
    bl is_hex_char
    cbz w0, skip
    add x12, x12, #1
    bl hex_char_to_nibble
    and w0, w0, #0xF
    tbz x12, #0, have_even
    lsl w6, w0, #4
    add x11, x11, #1
    b next_char
have_even:
    orr w5, w6, w0
    idx_from_linear x10, x3
    strb w5, [x2, x10]
    add x3, x3, #1
    add x11, x11, #1
    b next_char
skip:
    add x11, x11, #1
    b next_char
end_hex:
    cmp x3, #16
    cset w0, eq
    cbnz w0, ok_len
    print 1, key_err_msg, lenKeyErr
ok_len:
    ldp x29, x30, [sp], #16
    ret

// =======================
//   DEBUG / PRINT
// =======================
.type print_hex_byte, %function
print_hex_byte:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    and w10, w0, #0xFF
    lsr w1, w10, #4
    and w1, w1, #0x0F
    cmp w1, #10
    b.lt phb_high_digit
    add w1, w1, #('A' - 10)
    b phb_high_ok
phb_high_digit:
    add w1, w1, #'0'
phb_high_ok:
    and w2, w10, #0x0F
    cmp w2, #10
    b.lt phb_low_digit
    add w2, w2, #('A' - 10)
    b phb_low_ok
phb_low_digit:
    add w2, w2, #'0'
phb_low_ok:
    sub sp, sp, #16
    strb w1, [sp]
    strb w2, [sp, #1]
    mov w3, #' '
    strb w3, [sp, #2]
    mov x0, #1
    mov x1, sp
    mov x2, #3
    mov x8, #SYS_write
    svc #0
    add sp, sp, #16
    ldp x29, x30, [sp], #32
    ret

.type printMatrix, %function
.global printMatrix
printMatrix:
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x0, #1
    mov x1, x20
    mov x2, x21
    mov x8, #SYS_write
    svc #0
    mov x22, #0
row_loop:
    cmp x22, #4
    b.ge matrix_done
    mov x23, #0
col_loop:
    cmp x23, #4
    b.ge row_done
    mov x24, #4
    mul x24, x23, x24
    add x24, x24, x22
    ldrb w0, [x19, x24]
    bl print_hex_byte
    add x23, x23, #1
    b col_loop
row_done:
    mov x0, #1
    ldr x1, =newline
    mov x2, #1
    mov x8, #SYS_write
    svc #0
    add x22, x22, #1
    b row_loop
matrix_done:
    mov x0, #1
    ldr x1, =newline
    mov x2, #1
    mov x8, #SYS_write
    svc #0
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

.type print_if_debug, %function
print_if_debug:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    ldr x9, =debug_on
    ldrb w9, [x9]
    cbz w9, skip_print
    bl printMatrix
skip_print:
    ldp x29, x30, [sp], #16
    ret

.type printRoundKey, %function
.global printRoundKey
printRoundKey:
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    mov w19, w0
    sub sp, sp, #16
    mov x20, sp
    ldr x21, =round_keys
    uxtw x2, w19
    lsl x2, x2, #4
    add x21, x21, x2
    mov x3, #0
convert_loop:
    cmp x3, #4
    b.ge convert_done
    ldr w4, [x21, x3, lsl #2]
    ubfx w5, w4, #24, #8
    ubfx w6, w4, #16, #8
    ubfx w7, w4, #8,  #8
    ubfx w8, w4, #0,  #8
    strb w5, [x20, x3]
    add x9, x3, #4
    strb w6, [x20, x9]
    add x9, x3, #8
    strb w7, [x20, x9]
    add x9, x3, #12
    strb w8, [x20, x9]
    add x3, x3, #1
    b convert_loop
convert_done:
    mov x0, x20
    ldr x1, =debug_key
    mov x2, lenDebugKey
    bl printMatrix
    add sp, sp, #16
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

// =======================
//     AES PRIMITIVAS
// =======================
.type subBytes, %function
.global subBytes
subBytes:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    ldr x19, =matState
    ldr x20, =Sbox
    mov x0, #0
sb_loop:
    cmp x0, #16
    b.ge sb_done
    ldrb w1, [x19, x0]
    uxtw x1, w1
    ldrb w2, [x20, x1]
    strb w2, [x19, x0]
    add x0, x0, #1
    b sb_loop
sb_done:
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

.type shiftRows, %function
.global shiftRows
shiftRows:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    sub sp, sp, #32
    mov x20, sp
    ldr x19, =matState
    mov x0, #0
sr_cpy:
    cmp x0, #16
    b.ge sr_rows
    ldrb w1, [x19, x0]
    strb w1, [x20, x0]
    add x0, x0, #1
    b sr_cpy
sr_rows:
    ldrb w0, [x20, #4]
    ldrb w1, [x20, #5]
    ldrb w2, [x20, #6]
    ldrb w3, [x20, #7]
    strb w1, [x19, #4]
    strb w2, [x19, #5]
    strb w3, [x19, #6]
    strb w0, [x19, #7]
    ldrb w0, [x20, #8]
    ldrb w1, [x20, #9]
    ldrb w2, [x20, #10]
    ldrb w3, [x20, #11]
    strb w2, [x19, #8]
    strb w3, [x19, #9]
    strb w0, [x19, #10]
    strb w1, [x19, #11]
    ldrb w0, [x20, #12]
    ldrb w1, [x20, #13]
    ldrb w2, [x20, #14]
    ldrb w3, [x20, #15]
    strb w3, [x19, #12]
    strb w0, [x19, #13]
    strb w1, [x19, #14]
    strb w2, [x19, #15]
    add sp, sp, #32
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret

.type xtime, %function
xtime:
    and w1, w0, #0x80
    lsl w0, w0, #1
    and w0, w0, #0xFF
    cbz w1, xt_ret
    mov w1, #0x1B
    eor w0, w0, w1
xt_ret:
    ret

.type mixColumns, %function
.global mixColumns
mixColumns:
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    sub sp, sp, #32
    mov x20, sp
    ldr x19, =matState
    mov x0, #0
mc_cpy:
    cmp x0, #16
    b.ge mc_cols
    ldrb w1, [x19, x0]
    strb w1, [x20, x0]
    add x0, x0, #1
    b mc_cpy
mc_cols:
    mov x21, #0
mc_col_loop:
    cmp x21, #4
    b.ge mc_done
    mov x22, x21
    ldrb w4, [x20, x22]
    add x22, x22, #4
    ldrb w5, [x20, x22]
    add x22, x22, #4
    ldrb w6, [x20, x22]
    add x22, x22, #4
    ldrb w7, [x20, x22]
    mov w0, w4
    bl xtime
    mov w8, w0
    mov w0, w5
    bl xtime
    eor w9, w0, w5
    eor w10, w8, w9
    eor w10, w10, w6
    eor w10, w10, w7
    mov w0, w5
    bl xtime
    mov w11, w0
    mov w0, w6
    bl xtime
    eor w12, w0, w6
    eor w13, w4, w11
    eor w13, w13, w12
    eor w13, w13, w7
    mov w0, w6
    bl xtime
    mov w14, w0
    mov w0, w7
    bl xtime
    eor w15, w0, w7
    eor w25, w4, w5
    eor w25, w25, w14
    eor w25, w25, w15
    mov w0, w7
    bl xtime
    mov w26, w0
    mov w0, w4
    bl xtime
    eor w16, w0, w4
    eor w24, w16, w5
    eor w24, w24, w6
    eor w24, w24, w26
    mov x22, x21
    strb w10, [x19, x22]
    add x22, x22, #4
    strb w13, [x19, x22]
    add x22, x22, #4
    strb w25, [x19, x22]
    add x22, x22, #4
    strb w24, [x19, x22]
    add x21, x21, #1
    b mc_col_loop
mc_done:
    add sp, sp, #32
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

.type addRoundKey_rk, %function
.global addRoundKey_rk
addRoundKey_rk:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x2, #0
ark_col:
    cmp x2, #4
    b.ge ark_done
    add x3, x1, x2, lsl #2
    ldr w4, [x3]
    ubfx w5, w4, #24, #8
    ubfx w6, w4, #16, #8
    ubfx w7, w4, #8,  #8
    ubfx w8, w4, #0,  #8
    ldrb w9, [x0, x2]
    eor w9, w9, w5
    strb w9, [x0, x2]
    add x5, x2, #4
    ldrb w9, [x0, x5]
    eor w9, w9, w6
    strb w9, [x0, x5]
    add x5, x2, #8
    ldrb w9, [x0, x5]
    eor w9, w9, w7
    strb w9, [x0, x5]
    add x5, x2, #12
    ldrb w9, [x0, x5]
    eor w9, w9, w8
    strb w9, [x0, x5]
    add x2, x2, #1
    b ark_col
ark_done:
    ldp x29, x30, [sp], #16
    ret

// =======================
//     KEY EXPANSION
// =======================
.type keyExpansion, %function
.global keyExpansion
keyExpansion:
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    ldr x20, =key
    ldr x21, =round_keys
    ldr x22, =Sbox
    ldr x23, =Rcon
    mov x2, #0
kx_init_cols:
    cmp x2, #4
    b.ge kx_gen
    ldrb w5, [x20, x2]
    add x3, x2, #4
    ldrb w6, [x20, x3]
    add x3, x2, #8
    ldrb w7, [x20, x3]
    add x3, x2, #12
    ldrb w8, [x20, x3]
    lsl w5, w5, #24
    lsl w6, w6, #16
    lsl w7, w7, #8
    orr w4, w5, w6
    orr w4, w4, w7
    orr w4, w4, w8
    str w4, [x21, x2, lsl #2]
    add x2, x2, #1
    b kx_init_cols
kx_gen:
    mov w24, #4
word_loop:
    cmp w24, #44
    b.ge kx_done
    sub w1, w24, #1
    sub w2, w24, #4
    uxtw x1, w1
    uxtw x2, w2
    uxtw x0, w24
    add x25, x21, x1, lsl #2
    add x26, x21, x2, lsl #2
    add x27, x21, x0, lsl #2
    ldr w4, [x25]
    and w5, w24, #3
    cbnz w5, not_multiple_4
    ror w4, w4, #8
    ubfx w6, w4, #24, #8
    ubfx w7, w4, #16, #8
    ubfx w8, w4, #8,  #8
    ubfx w9, w4, #0,  #8
    uxtw x0, w6
    ldrb w6, [x22, x0]
    uxtw x0, w7
    ldrb w7, [x22, x0]
    uxtw x0, w8
    ldrb w8, [x22, x0]
    uxtw x0, w9
    ldrb w9, [x22, x0]
    lsl w6, w6, #24
    lsl w7, w7, #16
    lsl w8, w8, #8
    orr w4, w6, w7
    orr w4, w4, w8
    orr w4, w4, w9
    mov w1, #4
    udiv w10, w24, w1
    sub w10, w10, #1
    uxtw x12, w10
    lsl x12, x12, #2
    ldrb w11, [x23, x12]
    lsl w11, w11, #24
    eor w4, w4, w11
not_multiple_4:
    ldr w12, [x26]
    eor w13, w12, w4
    str w13, [x27]
    add w24, w24, #1
    b word_loop
kx_done:
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

// =======================
//   TIMING
// =======================
get_time_monotonic:
    sub sp, sp, #16
    mov x0, #CLOCK_MONOTONIC
    mov x1, sp
    mov x8, #SYS_clock_gettime
    svc #0
    ldr x0, [sp]
    ldr x1, [sp, #8]
    add sp, sp, #16
    ret

print_u64_nl:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    sub sp, sp, #32
    mov x20, sp
    add x21, x20, #31
    mov x22, #0
    mov x1, #10
1:  udiv x2, x0, x1
    msub x3, x2, x1, x0
    add x3, x3, #'0'
    strb w3, [x21]
    sub x21, x21, #1
    add x22, x22, #1
    mov x0, x2
    cbnz x0, 1b
    add x21, x21, #1
    mov x0, #1
    mov x1, x21
    mov x2, x22
    mov x8, #SYS_write
    svc #0
    mov x0, #1
    ldr x1, =newline
    mov x2, #1
    mov x8, #SYS_write
    svc #0
    add sp, sp, #32
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret

// =======================
//   AES ENCRYPT
// =======================
aes_encrypt:
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    ldr x19, =matState
    ldr x20, =round_keys
    mov x0, x19
    mov x1, x20
    bl addRoundKey_rk
    ldr x0, =matState
    ldr x1, =dbg_after_ark0
    mov x2, len_dbg_after_ark0
    bl print_if_debug
    mov w21, #1
rondas:
    cmp w21, #10
    b.ge ronda10
    bl subBytes
    ldr x0, =matState
    ldr x1, =dbg_after_sb
    mov x2, len_dbg_after_sb
    bl print_if_debug
    bl shiftRows
    ldr x0, =matState
    ldr x1, =dbg_after_sr
    mov x2, len_dbg_after_sr
    bl print_if_debug
    bl mixColumns
    ldr x0, =matState
    ldr x1, =dbg_after_mc
    mov x2, len_dbg_after_mc
    bl print_if_debug
    ldr x0, =matState
    mov x1, x20
    add x1, x1, w21, uxtw #4
    bl addRoundKey_rk
    ldr x0, =matState
    ldr x1, =dbg_after_ark
    mov x2, len_dbg_after_ark
    bl print_if_debug
    add w21, w21, #1
    b rondas
ronda10:
    bl subBytes
    ldr x0, =matState
    ldr x1, =dbg_after_sb
    mov x2, len_dbg_after_sb
    bl print_if_debug
    bl shiftRows
    ldr x0, =matState
    ldr x1, =dbg_after_sr
    mov x2, len_dbg_after_sr
    bl print_if_debug
    ldr x0, =matState
    ldr x1, =round_keys
    add x1, x1, #(10*16)
    bl addRoundKey_rk
    ldr x0, =matState
    ldr x1, =dbg_final
    mov x2, len_dbg_final
    bl print_if_debug
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #48
    ret

// =======================
//   PRINT CIPHER 
// =======================
.type printCipherHex, %function
.global printCipherHex
printCipherHex:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    
    print 1, cipher_msg, lenCipher
    ldr x19, =matState
    mov x20, #0              // ← USAR x20 COMO CONTADOR
pch_loop:
    cmp x20, #16
    b.ge pch_end
    ldrb w0, [x19, x20]      // ← cargar byte en w0
    bl print_hex_byte        // ← imprimir 
    add x20, x20, #1         // ← incrementar CONTADOR
    b pch_loop
pch_end:
    print 1, newline, 1
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

// =======================
//        MENU / MAIN
// =======================
.type _start, %function
.global _start
_start:
    ldr x0, =debug_on
    mov w1, #1
    strb w1, [x0]
menu_loop:
    print 1, menu_msg, lenMenu
    read 0, buffer, 16
    ldr x1, =buffer
    ldrb w0, [x1]
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
    b menu_loop
opt_text:
    print 1, msg_txt, lenMsgTxt
    bl readTextInput
    ldr x0, =has_text
    mov w1, #1
    strb w1, [x0]
    ldr x0, =matState
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix
    b menu_loop
opt_key:
    print 1, msg_key, lenMsgKey
    bl convertHexKey
    cbz w0, menu_loop
    ldr x0, =has_keyf
    mov w1, #1
    strb w1, [x0]
    ldr x0, =key
    ldr x1, =debug_key
    mov x2, lenDebugKey
    bl printMatrix
    b menu_loop
opt_run:
    ldr x0, =has_text
    ldrb w1, [x0]
    cbnz w1, has_txt_ok
    print 1, need_txt_msg, lenNeedTxt
    b menu_loop
has_txt_ok:
    ldr x0, =has_keyf
    ldrb w1, [x0]
    cbnz w1, has_key_ok
    print 1, need_key_msg, lenNeedKey
    b menu_loop
has_key_ok:
    print 1, run_msg, lenRun
    bl keyExpansion
    ldr x9, =debug_on
    ldrb w9, [x9]
    cbz w9, skip_keys
    mov w20, #0
keys_loop:
    cmp w20, #11
    b.ge keys_done
    mov w0, w20
    bl printRoundKey
    add w20, w20, #1
    b keys_loop
keys_done:
skip_keys:
    bl get_time_monotonic
    mov x26, x0
    mov x27, x1
    bl aes_encrypt
    bl get_time_monotonic
    sub x0, x0, x26
    ldr x2, =1000000000
    mul x0, x0, x2
    sub x1, x1, x27
    add x0, x0, x1
    print 1, tmsg, lenT
    bl print_u64_nl
    bl printCipherHex
    print 1, done_msg, lenDone
    b menu_loop
opt_info:
    print 1, info_msg, lenInfo
    b menu_loop
opt_exit:
    mov x0, #0
    mov x8, #SYS_exit
    svc #0