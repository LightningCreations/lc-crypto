pub unsafe fn eq_bytes_secure_impl(a: *const u8, b: *const u8, len: usize) -> bool {
    let mut res: u8;
    cfg_match::cfg_match! {
        target_arch = "x86_64" => unsafe { core::arch::asm!{
            "xor eax, eax",
            "mov r8, 1",
            "cmp rcx, 16",
            "jb 3f",
            "2:",
            "movdqu xmm0, xmmword ptr [rdi]",
            "movdqu xmm1, xmmword ptr [rsi]",
            "ptest xmm0, xmm1",
            "cmovnc rax, r8",
            "lea rdi, [rdi+16]",
            "lea rsi, [rsi+16]",
            "lea rcx, [rcx-16]",
            "cmp rcx, 16",
            "jae 2b",
            "3:",
            "cmp rcx, 8",
            "jb 3f",
            "mov rdx, qword ptr [rdi]",
            "cmp rdx, qword ptr [rsi]",
            "cmovne rax, r8",
            "lea rdi, [rdi+8]",
            "lea rsi, [rsi+8]",
            "lea rcx, [rcx-8]",
            "3:",
            "cmp rcx, 4",
            "jb 3f",
            "mov edx, dword ptr [rdi]",
            "cmp edx, dword ptr [rsi]",
            "cmovne rax, r8",
            "lea rdi, [rdi+4]",
            "lea rsi, [rsi+4]",
            "lea rcx, [rcx-4]",
            "3:",
            "cmp rcx, 2",
            "jb 3f",
            "mov dx, word ptr [rdi]",
            "cmp dx, word ptr [rsi]",
            "cmovne rax, r8",
            "lea rdi, [rdi+2]",
            "lea rsi, [rsi+2]",
            "lea rcx, [rcx-2]",
            "3:",
            "cmp rcx, 1",
            "jb 3f",
            "mov dl, byte ptr [rdi]",
            "cmp dl, byte ptr [rsi]",
            "cmovne rax, r8",
            "3:",
            inout("rdi") a=> _,
            inout("rsi") b=> _,
            inout("rcx") len => _,
            out("rdx") _,
            out("al") res,
            out("r8") _,
            out("xmm0") _,
            out("xmm1") _,
            options(nostack, readonly, pure),
        } },

        // target_arch = "x86" => unsafe { core::arch::asm!{
        //     "xor eax, eax",
        //     "cmp ecx, 4",
        //     "jb 3f",
        //     "2:",
        //     "mov edx, dword ptr [edi]",
        //     "cmp edx, dword ptr [esi]",
        //     "setne al",
        //     "lea edi, [edi+4]",
        //     "lea esi, [esi+4]",
        //     "lea ecx, [ecx-4]",
        //     "cmp ecx, 8",
        //     "jae 2b",
        //     "3:",
        //     "cmp ecx, 2",
        //     "jb 3f",
        //     "mov dx, word ptr [edi]",
        //     "cmp dx, word ptr [esi]",
        //     "setne al",
        //     "lea edi, [edi+2]",
        //     "lea esi, [esi+2]",
        //     "lea ecx, [ecx-2]",
        //     "3:",
        //     "cmp ecx, 1"
        //     "jb 3f",
        //     "cmp ecx, 4",
        //     "jb 3f",
        //     "mov dl, byte ptr [edi]",
        //     "cmp dl, byte ptr [esi]",
        //     "setne al",
        //     inout("edi") a=> _,
        //     inout("esi") b=> _,
        //     inout("ecx") len => _,
        //     out("edx") _,
        //     out("eax") res,
        //     options(nostack, readonly, pure),
        // } },

        _ => {
            res = 0;

            unsafe{let _ = a.add(len);}
            unsafe{let _ = b.add(len);}

            // black_box may not be perfect for preventing side channels, but it's as good as it gets
            for i in 0..len {
                res = core::hint::black_box(res | (unsafe{a.add(i).volatile_read() != b.add(i).volatile_read()}))
            }
        }
    }

    // res is "Are the bytes unequal anywhere"
    !unsafe { core::mem::transmute(res) }
}
