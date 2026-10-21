(assert (let ((a!1 (ite (bvslt #x00000000 #x00000000)
                (- (bv2int #x00000000) 4294967296)
                (bv2int #x00000000))))
(let ((a!2 (< a!1
              (ite (bvslt #x00002000 #x00000000)
                   (- (bv2int #x00002000) 4294967296)
                   (bv2int #x00002000)))))
  (not (and (>= a!1 a!1) a!2)))))
