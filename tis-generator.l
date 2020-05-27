// PicoLisp tis.config file generator

(setq
   *M
   (quote
      sparc_64 sparc_32
      armeb_eabi arm_eabi aarch64 aarch64eb
      rv64ifdq rv32ifdq
      mips_o32 mips_n32 mips_64 mipsel_64
      x86_16 x86_16_huge x86_32 x86_64 )
   *F
   (quote
      p1305 blake2b )
   *L
   (make
      (for F *F
         (for M *M
            (link (cons F M)) ) ) ) )
(out "tis.config"
   (prinl "// Auto genetated file")
   (prinl "[")
   (for (L *L L (cdr L))
      (let (F (caar L)  M (cdar L))
         (prinl "{")
         (prinl "\"name\":" (pack "\"" F " - " M "\"") ",")
         (prinl "\"files\":\"all\",")
         (prinl "\"machdep\":\"" M "\",")
         (prinl "\"main\":\"" F "\"")
         (prin "}")
         (and (cdr L) (prinl ",")) ) )
   (prinl "]") )
(bye)
